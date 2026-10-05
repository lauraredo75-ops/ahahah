<#
  re-common.ps1 — helpers partages du systeme RE "mze".
  Dot-source :  . 'D:\mze\lib\re-common.ps1'

  Fournit : resolution d'outils via le manifeste D:\re-tools\tools.json,
  creation d'un run-dir horodate (avec COPIE du binaire — l'original n'est
  jamais touche), journalisation reproductible, E/S JSON normalisees.
#>

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

# Racine toolchain (surchargée par $env:RE_TOOLS_ROOT)
$script:ReToolsRoot = if ($env:RE_TOOLS_ROOT) { $env:RE_TOOLS_ROOT } else { 'D:\re-tools' }
$script:ReProjectRoot = Split-Path $PSScriptRoot -Parent   # D:\mze

# --------------------------------------------------------------------------
# Manifeste / resolution d'outils
# --------------------------------------------------------------------------
function Get-ReManifest {
  $p = Join-Path $script:ReToolsRoot 'tools.json'
  if (-not (Test-Path $p)) { return $null }
  Get-Content $p -Raw | ConvertFrom-Json
}

# Renvoie un objet { name; path; invoke; kind } ou $null
function Resolve-ReTool {
  param([Parameter(Mandatory)][string]$Name)
  $m = Get-ReManifest
  if (-not $m) { return $null }
  $t = $m.tools.$Name
  if (-not $t) { return $null }
  if (-not (Test-Path $t.path)) { return $null }
  [pscustomobject]@{ name=$Name; path=$t.path; invoke=$t.invoke; kind=$t.kind }
}

function Test-ReTool { param([string]$Name) [bool](Resolve-ReTool -Name $Name) }

# Positionne JAVA_HOME sur le JDK 21 du manifeste (requis par Ghidra 12). Renvoie le home ou $null.
function Set-ReGhidraJava {
  $t = Resolve-ReTool 'jdk21'
  if ($t) { $env:JAVA_HOME = $t.path; return $t.path }
  Write-Host (Get-ReToolHint 'jdk')
  return $null
}

# Commande d'installation a afficher si un outil manque
function Get-ReToolHint {
  param([string]$Name)
  "MANQUANT: '$Name'. Installer avec :  powershell -ExecutionPolicy Bypass -File $($script:ReProjectRoot)\tools\install.ps1 -Only $Name"
}

# --------------------------------------------------------------------------
# Run-dir : 1 dossier horodate par analyse, binaire COPIE dedans
# --------------------------------------------------------------------------
function New-ReRun {
  param(
    [Parameter(Mandatory)][string]$Binary,
    [string]$ProjectRoot = $script:ReProjectRoot
  )
  if (-not (Test-Path $Binary)) { throw "Binaire introuvable : $Binary" }
  $src  = (Resolve-Path $Binary).Path
  $name = [IO.Path]::GetFileNameWithoutExtension($src)
  $safe = ($name -replace '[^A-Za-z0-9._-]','_')
  $ts   = Get-Date -Format 'yyyyMMdd-HHmmss'
  $run  = Join-Path $ProjectRoot ("out\{0}__{1}" -f $ts, $safe)
  foreach ($d in @($run, (Join-Path $run 'logs'), (Join-Path $run 'artifacts'))) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
  }
  $ext  = [IO.Path]::GetExtension($src)
  $copy = Join-Path $run ("sample{0}" -f $ext)
  Copy-Item -LiteralPath $src -Destination $copy -Force

  $h = (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash
  $meta = [ordered]@{
    original = $src ; binary = $copy ; name = $name
    sha256 = $h ; size = (Get-Item $copy).Length
    started = (Get-Date).ToString('o') ; run_dir = $run
    tools_root = $script:ReToolsRoot
  }
  Write-ReJson $meta (Join-Path $run 'run.json')
  Add-ReLog $run "RUN cree pour $src (sha256=$h)"
  [pscustomobject]@{ run=$run; binary=$copy; name=$name; ts=$ts; sha256=$h
                     artifacts=(Join-Path $run 'artifacts'); logs=(Join-Path $run 'logs') }
}

# --------------------------------------------------------------------------
# JSON normalise
# --------------------------------------------------------------------------
function Write-ReJson { param($Object,[string]$Path) $Object | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path -Encoding utf8 }
function Read-ReJson  { param([string]$Path) if (Test-Path $Path) { Get-Content $Path -Raw | ConvertFrom-Json } }

# Squelette de findings commun a tous les sous-agents
function New-ReFindings {
  param([string]$Agent,[string]$Status='ok')
  [ordered]@{
    agent        = $Agent
    status       = $Status            # ok | partial | failed | tool_missing
    binary_type  = $null
    confidence   = 0.0
    recovered    = [ordered]@{ kind='none'; paths=@() }  # source|pseudocode|bytecode|resources|none
    entrypoints  = @()
    notable      = @()
    limitations  = @()
    tools_used   = @()
    missing_tools= @()
    route_next   = @()
    generated    = (Get-Date).ToString('o')
  }
}

# --------------------------------------------------------------------------
# Journalisation
# --------------------------------------------------------------------------
function Add-ReLog {
  param([string]$Run,[string]$Message)
  $line = ('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message)
  Add-Content -LiteralPath (Join-Path $Run 'logs\orchestrator.log') -Value $line
  Write-Host $line
}

# --------------------------------------------------------------------------
# Execution d'un outil, journalisee et reproductible
#   Invoke-ReTool -Name ilspycmd -Arguments @('sample.exe','-o','out') -Run $run
#   -> ecrit logs\<name>.log, ajoute la commande exacte a logs\commands.txt
#   -> renvoie { exit; log; ok }
# --------------------------------------------------------------------------
function Invoke-ReTool {
  param(
    [Parameter(Mandatory)][string]$Name,
    [string[]]$Arguments = @(),
    [Parameter(Mandatory)][string]$Run,
    [string]$StepLabel
  )
  $tool = Resolve-ReTool -Name $Name
  if (-not $tool) {
    Add-ReLog $Run (Get-ReToolHint $Name)
    return [pscustomobject]@{ exit=$null; ok=$false; log=$null; missing=$true }
  }
  if (-not $StepLabel) { $StepLabel = $Name }
  $log = Join-Path $Run ("logs\{0}.log" -f ($StepLabel -replace '[^A-Za-z0-9._-]','_'))

  if ($tool.kind -eq 'jar') {
    $exe = 'java' ; $full = @('-jar', $tool.path) + $Arguments
  } else {
    $exe = $tool.path ; $full = $Arguments
  }
  $printable = ('"{0}" {1}' -f $exe, ($full -join ' '))
  Add-Content -LiteralPath (Join-Path $Run 'logs\commands.txt') -Value $printable
  Add-ReLog $Run ("EXEC {0}" -f $printable)

  try {
    & $exe @full *>&1 | Tee-Object -FilePath $log | Out-Null
    $code = $LASTEXITCODE
  } catch {
    Add-Content -LiteralPath $log -Value ("[ERREUR] " + $_.Exception.Message)
    $code = 1
  }
  [pscustomobject]@{ exit=$code; ok=($code -eq 0 -or $code -eq $null); log=$log; missing=$false }
}

# Detection UPX (signature + sections). Renvoie $true si packe UPX.
function Test-ReUpx {
  param([Parameter(Mandatory)][string]$Binary)
  try {
    $bytes = [IO.File]::ReadAllBytes($Binary)
    $txt = [Text.Encoding]::ASCII.GetString($bytes)
    return ($txt -match 'UPX[0-9!]')
  } catch { return $false }
}

# --------------------------------------------------------------------------
# Auto-amélioration : consigne une leçon dans knowledge\lessons.md (dédup par titre).
# Utilisé par synthese / l'orchestrateur quand une erreur a été rencontrée et résolue.
# --------------------------------------------------------------------------
function Add-ReLesson {
  param(
    [Parameter(Mandatory)][string]$Title,
    [string]$Symptome,
    [string]$Cause,
    [string]$Correctif
  )
  $kb = Join-Path $script:ReProjectRoot 'knowledge\lessons.md'
  if (-not (Test-Path $kb)) { return $false }
  if (Select-String -LiteralPath $kb -SimpleMatch $Title -Quiet) { return $false }  # déjà consignée
  $date = Get-Date -Format 'yyyy-MM-dd'
  $lines = @('', "## $date - $Title")
  if ($Symptome)  { $lines += "- **Symptôme** : $Symptome" }
  if ($Cause)     { $lines += "- **Cause** : $Cause" }
  if ($Correctif) { $lines += "- **Correctif** : $Correctif" }
  Add-Content -LiteralPath $kb -Value ($lines -join "`r`n") -Encoding utf8
  return $true
}


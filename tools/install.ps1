<#
.SYNOPSIS
  Installe la toolchain de reverse-engineering / decompilation du projet "mze"
  sur le disque D:, sans droits administrateur, depuis les sources officielles.

.DESCRIPTION
  Idempotent + journalise. Chaque outil est :
    - telecharge/installe sous $Root (defaut D:\re-tools)
    - enregistre dans $Root\tools.json (manifeste lu par les sous-agents)
    - expose via un shim .cmd dans $Root\bin (ajoute au PATH utilisateur)
  Une panne sur un outil n'interrompt pas les autres : resume final en fin de run.

.PARAMETER Root
  Racine d'installation de la toolchain. Defaut: D:\re-tools

.PARAMETER Only
  Sous-ensemble d'outils a (re)installer, ex: -Only die,upx,ghidra

.PARAMETER Force
  Reinstalle meme si deja present.

.PARAMETER NoPath
  N'ajoute pas $Root\bin au PATH utilisateur.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File D:\mze\tools\install.ps1
  powershell -ExecutionPolicy Bypass -File D:\mze\tools\install.ps1 -Only ghidra,radare2 -Force
#>
[CmdletBinding()]
param(
  [string]   $Root  = 'D:\re-tools',
  [string[]] $Only,
  [switch]   $Force,
  [switch]   $NoPath
)

$ProgressPreference    = 'SilentlyContinue'   # Invoke-WebRequest bien plus rapide
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Robustesse : en mode -File, "-Only a,b,c" arrive comme une seule chaine -> on la redecoupe.
if ($Only -and $Only.Count -eq 1 -and $Only[0] -match ',') { $Only = $Only[0] -split '\s*,\s*' }

# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------
$BinDir  = Join-Path $Root 'bin'
$SrcDir  = Join-Path $Root 'src'
$DlDir   = Join-Path $Root 'dl'
$LogDir  = Join-Path $Root 'logs'
foreach ($d in @($Root,$BinDir,$SrcDir,$DlDir,$LogDir)) {
  if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
}

$stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
Start-Transcript -Path (Join-Path $LogDir "install-$stamp.log") -Append | Out-Null

$script:Results  = [ordered]@{}        # name -> 'OK' | 'SKIP' | 'FAIL: reason'
$script:Manifest = [ordered]@{}        # name -> @{ path; invoke; kind }

function Say  ($m){ Write-Host "[*]  $m" -ForegroundColor Cyan }
function Good ($m){ Write-Host "[OK] $m" -ForegroundColor Green }
function Warn ($m){ Write-Host "[!!] $m" -ForegroundColor Yellow }
function ShouldRun ($name){
  if ($Only -and ($Only -notcontains $name)) { $script:Results[$name]='SKIP (not in -Only)'; return $false }
  return $true
}
function Have ($exe){ [bool](Get-Command $exe -ErrorAction SilentlyContinue) }

function Download ($url,$out){
  for ($i=1; $i -le 3; $i++) {
    try   { Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $out -TimeoutSec 180; return }
    catch { if ($i -eq 3) { throw } ; Start-Sleep -Seconds (2*$i) }
  }
}

function GHAsset ($repo,$pattern){
  $hdr = @{ 'User-Agent' = 'mze-re-setup' }
  $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers $hdr -TimeoutSec 60
  $a   = $rel.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
  if (-not $a) { throw "aucun asset '$pattern' dans $repo ($($rel.tag_name))" }
  return $a.browser_download_url
}

function ExpandTo ($zip,$dest){
  if (Test-Path $dest) { Remove-Item $dest -Recurse -Force -ErrorAction SilentlyContinue }
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  Expand-Archive -Path $zip -DestinationPath $dest -Force
}

function Register ($name,$path,$invoke,$kind){
  $script:Manifest[$name] = [ordered]@{ path=$path; invoke=$invoke; kind=$kind }
}

# Cree $Root\bin\<name>.cmd. kind: exe | jar | bat | raw
function Shim ($name,$target,$kind,[string]$extra=''){
  $cmd = Join-Path $BinDir "$name.cmd"
  switch ($kind) {
    'exe' { $line = "`"$target`" %*" }
    'bat' { $line = "call `"$target`" %*" }
    'jar' { $line = "java -jar `"$target`" %*" }
    'raw' { $line = $extra }                       # ligne complete fournie
    default { $line = "`"$target`" %*" }
  }
  Set-Content -Path $cmd -Value "@echo off`r`n$line" -Encoding ascii
}

# Wrapper standard d'install d'un outil
function Tool ($name,[scriptblock]$body){
  if (-not (ShouldRun $name)) { Warn "$name : saute (-Only)"; return }
  try   { Say "$name ..." ; & $body ; if ($script:Results[$name] -notlike 'SKIP*') { $script:Results[$name]='OK' ; Good "$name" } }
  catch { $script:Results[$name]="FAIL: $($_.Exception.Message)" ; Warn "$name : $($_.Exception.Message)" }
}

function MarkerOk ($path){ if ([string]::IsNullOrEmpty($path)) { return $false } ; return ((-not $Force) -and (Test-Path $path)) }

# ---------------------------------------------------------------------------
# TRIAGE
# ---------------------------------------------------------------------------
Tool 'die' {
  $dest = Join-Path $Root 'die'
  $exe  = Get-ChildItem $dest -Recurse -Filter 'diec.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not (MarkerOk $exe.FullName)) {
    $url = GHAsset 'horsicq/DIE-engine' '(?i)win64.*portable.*\.zip$'
    $zip = Join-Path $DlDir 'die.zip' ; Download $url $zip ; ExpandTo $zip $dest
    $exe = Get-ChildItem $dest -Recurse -Filter 'diec.exe' | Select-Object -First 1
  }
  if (-not $exe) { throw 'diec.exe introuvable apres extraction' }
  Shim 'diec' $exe.FullName 'exe' ; Register 'die' $exe.FullName 'diec' 'cli'
}

Tool 'trid' {
  $dest = Join-Path $Root 'trid'
  if (-not (MarkerOk (Join-Path $dest 'trid.exe'))) {
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Download 'https://mark0.net/download/trid_w32.zip'  (Join-Path $DlDir 'trid.zip')
    Download 'https://mark0.net/download/triddefs.zip'  (Join-Path $DlDir 'triddefs.zip')
    Expand-Archive (Join-Path $DlDir 'trid.zip')     $dest -Force
    Expand-Archive (Join-Path $DlDir 'triddefs.zip') $dest -Force
  }
  $exe = Join-Path $dest 'trid.exe'
  if (-not (Test-Path $exe)) { throw 'trid.exe introuvable' }
  # TrID veut tourner depuis son dossier (triddefs.trd)
  Shim 'trid' $exe 'raw' "cd /d `"$dest`" && `"$exe`" %*"
  Register 'trid' $exe 'trid' 'cli'
}

Tool 'upx' {
  $dest = Join-Path $Root 'upx'
  $exe  = Get-ChildItem $dest -Recurse -Filter 'upx.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not (MarkerOk $exe.FullName)) {
    $url = GHAsset 'upx/upx' 'win64\.zip$'
    $zip = Join-Path $DlDir 'upx.zip' ; Download $url $zip ; ExpandTo $zip $dest
    $exe = Get-ChildItem $dest -Recurse -Filter 'upx.exe' | Select-Object -First 1
  }
  if (-not $exe) { throw 'upx.exe introuvable' }
  Shim 'upx' $exe.FullName 'exe' ; Register 'upx' $exe.FullName 'upx' 'cli'
}

Tool 'strings' {
  $dest = Join-Path $Root 'sysinternals'
  if (-not (MarkerOk (Join-Path $dest 'strings64.exe'))) {
    $zip = Join-Path $DlDir 'strings.zip'
    Download 'https://download.sysinternals.com/files/Strings.zip' $zip
    ExpandTo $zip $dest
  }
  # Strings.zip contient strings.exe (x86), strings64.exe (x64), strings64a.exe (ARM64).
  # On veut le x64 ; surtout pas la variante ARM64 (64a).
  $exe = Get-ChildItem $dest -Filter 'strings64.exe' | Select-Object -First 1
  if (-not $exe) { $exe = Get-ChildItem $dest -Filter 'strings*.exe' | Where-Object { $_.Name -notmatch '64a' } | Sort-Object Name -Descending | Select-Object -First 1 }
  if (-not $exe) { throw 'strings.exe introuvable' }
  # /accepteula pour eviter le prompt EULA au 1er run
  Shim 'strings' $exe.FullName 'raw' "`"$($exe.FullName)`" /accepteula -nobanner %*"
  Register 'strings' $exe.FullName 'strings' 'cli'
}

Tool 'capa' {
  $dest = Join-Path $Root 'capa'
  if (-not (MarkerOk (Join-Path $dest 'capa.exe'))) {
    $url = GHAsset 'mandiant/capa' 'windows\.zip$'
    $zip = Join-Path $DlDir 'capa.zip' ; Download $url $zip ; ExpandTo $zip $dest
  }
  $exe = Get-ChildItem $dest -Recurse -Filter 'capa.exe' | Select-Object -First 1
  if (-not $exe) { throw 'capa.exe introuvable' }
  Shim 'capa' $exe.FullName 'exe' ; Register 'capa' $exe.FullName 'capa' 'cli'
}

Tool 'floss' {
  $dest = Join-Path $Root 'floss'
  if (-not (MarkerOk (Join-Path $dest 'floss.exe'))) {
    $url = GHAsset 'mandiant/flare-floss' 'windows\.zip$'
    $zip = Join-Path $DlDir 'floss.zip' ; Download $url $zip ; ExpandTo $zip $dest
  }
  $exe = Get-ChildItem $dest -Recurse -Filter 'floss.exe' | Select-Object -First 1
  if (-not $exe) { throw 'floss.exe introuvable' }
  Shim 'floss' $exe.FullName 'exe' ; Register 'floss' $exe.FullName 'floss' 'cli'
}

# binwalk v3 (Rust) ne publie pas de binaire Windows ; non critique (7z + strings couvrent
# l'inspection de conteneur au triage). On le marque optionnel sans echouer.
if (ShouldRun 'binwalk') {
  $script:Results['binwalk'] = 'SKIP (optionnel, pas de build Windows)'
  Warn 'binwalk : optionnel, indisponible sous Windows — ignore (7z + strings prennent le relais)'
}

# ---------------------------------------------------------------------------
# .NET
# ---------------------------------------------------------------------------
Tool 'ilspycmd' {
  $dest = Join-Path $Root 'ilspycmd'
  $exe  = Join-Path $dest 'ilspycmd.exe'
  if (-not (MarkerOk $exe)) {
    if (-not (Have 'dotnet')) { throw 'dotnet SDK absent' }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    # nuget.config propre : force nuget.org uniquement (contourne un feed prive cassé)
    $cfg = Join-Path $dest 'nuget.config'
    $xml = @('<?xml version="1.0" encoding="utf-8"?>','<configuration><packageSources><clear/>','<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />','</packageSources></configuration>') -join "`r`n"
    Set-Content -LiteralPath $cfg -Value $xml -Encoding ascii
    $o = ''
    foreach ($ver in @('8.2.0.7535','9.1.0.7988')) {
      $o += (& dotnet tool install ilspycmd --tool-path $dest --version $ver --configfile $cfg 2>&1 | Out-String)
      if (Test-Path $exe) { break }
    }
    if (-not (Test-Path $exe)) { $o += (& dotnet tool install ilspycmd --tool-path $dest --configfile $cfg 2>&1 | Out-String) }
    if (-not (Test-Path $exe)) {
      $any = Get-ChildItem $dest -Filter '*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($any) { $exe = $any.FullName } else { throw ('dotnet: ' + (($o -replace '\s+',' ').Trim())) }
    }
  }
  if (-not (Test-Path $exe)) { throw 'ilspycmd.exe introuvable' }
  Shim 'ilspycmd' $exe 'exe' ; Register 'ilspycmd' $exe 'ilspycmd' 'cli'
}

# de4dot : deobfuscateur .NET (ConfuserEx, etc.). Utilise par l'agent dotnet/deobfuscation.
Tool 'de4dot' {
  $dest = Join-Path $Root 'de4dot'
  $exe  = Get-ChildItem $dest -Recurse -Filter 'de4dot.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not (MarkerOk $exe.FullName)) {
    $url = GHAsset 'ViRb3/de4dot-cex' '(?i)de4dot.*\.zip$'
    $zip = Join-Path $DlDir 'de4dot.zip' ; Download $url $zip ; ExpandTo $zip $dest
    $exe = Get-ChildItem $dest -Recurse -Filter 'de4dot.exe' | Select-Object -First 1
  }
  if (-not $exe) { throw 'de4dot.exe introuvable' }
  Shim 'de4dot' $exe.FullName 'exe' ; Register 'de4dot' $exe.FullName 'de4dot' 'cli'
}

# ---------------------------------------------------------------------------
# JAVA
# ---------------------------------------------------------------------------
Tool 'cfr' {
  $dest = Join-Path $Root 'java' ; New-Item -ItemType Directory -Force -Path $dest | Out-Null
  $jar  = Join-Path $dest 'cfr.jar'
  if (-not (MarkerOk $jar)) {
    $url = GHAsset 'leibnitz27/cfr' '^cfr-.*\.jar$'
    Download $url $jar
  }
  Shim 'cfr' $jar 'jar' ; Register 'cfr' $jar 'cfr' 'jar'
}

Tool 'procyon' {
  $dest = Join-Path $Root 'java' ; New-Item -ItemType Directory -Force -Path $dest | Out-Null
  $jar  = Join-Path $dest 'procyon-decompiler.jar'
  if (-not (MarkerOk $jar)) {
    $url = GHAsset 'mstrobel/procyon' '(?i)procyon-decompiler.*\.jar$'
    Download $url $jar
  }
  Shim 'procyon' $jar 'jar' ; Register 'procyon' $jar 'procyon' 'jar'
}

Tool 'jd-cli' {
  $dest = Join-Path $Root 'jd-cli'
  if (-not (MarkerOk (Join-Path $dest 'jd-cli.jar'))) {
    $url = GHAsset 'intoolswetrust/jd-cli' 'dist\.zip$'
    $zip = Join-Path $DlDir 'jd-cli.zip' ; Download $url $zip ; ExpandTo $zip $dest
  }
  $jar = Get-ChildItem $dest -Recurse -Filter 'jd-cli*.jar' | Select-Object -First 1
  if (-not $jar) { throw 'jd-cli jar introuvable' }
  Shim 'jd-cli' $jar.FullName 'jar' ; Register 'jd-cli' $jar.FullName 'jd-cli' 'jar'
}

Tool 'jadx' {
  $dest = Join-Path $Root 'jadx'
  $bat  = Get-ChildItem $dest -Recurse -Filter 'jadx.bat' -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not (MarkerOk $bat.FullName)) {
    $url = GHAsset 'skylot/jadx' '^jadx-\d+\.\d+\.\d+\.zip$'
    $zip = Join-Path $DlDir 'jadx.zip' ; Download $url $zip ; ExpandTo $zip $dest
    $bat = Get-ChildItem $dest -Recurse -Filter 'jadx.bat' | Select-Object -First 1
  }
  if (-not $bat) { throw 'jadx.bat introuvable' }
  Shim 'jadx' $bat.FullName 'bat' ; Register 'jadx' $bat.FullName 'jadx' 'cli'
}

# ---------------------------------------------------------------------------
# PYTHON  (venv isole sur D:)
# ---------------------------------------------------------------------------
Tool 'pyenv' {
  $venv = Join-Path $Root 'venv'
  $pyexe = Join-Path $venv 'Scripts\python.exe'
  if (-not (MarkerOk $pyexe)) {
    $base = $null
    foreach ($v in '3.10','3.9','3.13') {
      try { & py "-$v" -c "import sys" 2>$null; if ($LASTEXITCODE -eq 0) { $base=$v; break } } catch {}
    }
    if (-not $base) { throw 'aucun interpreteur py -3.x trouve' }
    & py "-$base" -m venv $venv
  }
  & $pyexe -m pip install --quiet --upgrade pip 2>&1 | Out-Host
  & $pyexe -m pip install --quiet uncompyle6 decompyle3 xdis pyinstxtractor-ng pefile capstone 2>&1 | Out-Host
  Register 'python-venv' $pyexe 'python' 'runtime'

  # pyinstxtractor-ng expose une commande console dans le venv
  $pix = Join-Path $venv 'Scripts\pyinstxtractor-ng.exe'
  if (Test-Path $pix) { Shim 'pyinstxtractor' $pix 'exe' ; Register 'pyinstxtractor' $pix 'pyinstxtractor' 'cli' }
  # decompilateurs bytecode
  foreach ($t in 'uncompyle6','decompyle3','pydisasm') {
    $e = Join-Path $venv "Scripts\$t.exe"
    if (Test-Path $e) { Shim $t $e 'exe' ; Register $t $e $t 'cli' }
  }
}

Tool 'pycdc' {
  # Decompilateur pour bytecode Python recent (3.10+). Build MSVC + CMake.
  $dest = Join-Path $Root 'pycdc'
  $built = Get-ChildItem (Join-Path $dest 'build') -Recurse -Filter 'pycdc.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($built -and -not $Force) {
    Shim 'pycdc' $built.FullName 'exe' ; Register 'pycdc' $built.FullName 'pycdc' 'cli'
    $d0 = Get-ChildItem (Join-Path $dest 'build') -Recurse -Filter 'pycdas.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($d0) { Shim 'pycdas' $d0.FullName 'exe' ; Register 'pycdas' $d0.FullName 'pycdas' 'cli' }
    return
  }

  # pycdc doit etre linke avec MSVC : le Windows SDK (rc.exe/mt.exe) est requis.
  $sdkRc = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter 'rc.exe' -ErrorAction SilentlyContinue |
           Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
  if (-not $sdkRc) {
    $script:Results['pycdc'] = 'SKIP (Windows 10 SDK requis : rc.exe/mt.exe absents ; Python <=3.9 couvert, 3.10+ via pydisasm/pylingual)'
    Warn 'pycdc : Windows 10 SDK manquant (rc.exe/mt.exe). Installer le SDK via Visual Studio Installer puis relancer -Only pycdc. Repli : pydisasm (bytecode) / pylingual.'
    return
  }
  if (-not (Have 'git')) { throw 'git absent' }
  # localiser cmake : PATH, sinon VS BuildTools, sinon CMake portable telecharge sur D:
  $cmake = (Get-Command cmake -ErrorAction SilentlyContinue).Source
  if (-not $cmake) {
    $vsw = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vsw) {
      $vs = (& $vsw -latest -products * -property installationPath)
      if ($vs) { $c = Get-ChildItem $vs -Recurse -Filter cmake.exe -ErrorAction SilentlyContinue | Select-Object -First 1; if ($c) { $cmake = $c.FullName } }
    }
  }
  if (-not $cmake) {
    $cmakeDir = Join-Path $Root 'cmake'
    $ce = Get-ChildItem $cmakeDir -Recurse -Filter cmake.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $ce) {
      $url = GHAsset 'Kitware/CMake' '(?i)windows-x86_64\.zip$'
      $zip = Join-Path $DlDir 'cmake.zip' ; Download $url $zip ; ExpandTo $zip $cmakeDir
      $ce  = Get-ChildItem $cmakeDir -Recurse -Filter cmake.exe | Select-Object -First 1
    }
    if ($ce) { $cmake = $ce.FullName }
  }
  if (-not $cmake) { throw 'cmake introuvable' }

  if (-not (Test-Path (Join-Path $dest 'CMakeLists.txt'))) {
    & git clone --depth 1 https://github.com/zrax/pycdc $dest 2>&1 | Out-Host
  }
  $build = Join-Path $dest 'build'
  # Build via NMake dans l'environnement VS (evite le choix du generateur VS 2019/2022)
  # vswhere est inopérant ici : on cherche VsDevCmd.bat directement sous les racines VS.
  $vsroots = @("${env:ProgramFiles(x86)}\Microsoft Visual Studio", "$env:ProgramFiles\Microsoft Visual Studio") | Where-Object { Test-Path $_ }
  $vsdev = Get-ChildItem $vsroots -Recurse -Filter 'VsDevCmd.bat' -Depth 4 -ErrorAction SilentlyContinue |
           Sort-Object FullName | Select-Object -First 1 -ExpandProperty FullName
  if (-not $vsdev) { throw 'VsDevCmd.bat introuvable (VS Build Tools requis pour builder pycdc)' }
  if (Test-Path $build) { Remove-Item $build -Recurse -Force -ErrorAction SilentlyContinue }
  $line = "call `"$vsdev`" -arch=amd64 -host_arch=amd64 && `"$cmake`" -S `"$dest`" -B `"$build`" -G `"NMake Makefiles`" -DCMAKE_BUILD_TYPE=Release && `"$cmake`" --build `"$build`""
  & cmd /c $line 2>&1 | Out-Host

  $pycdc = Get-ChildItem $build -Recurse -Filter 'pycdc.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $pycdc) { throw 'build pycdc echoue' }
  Shim 'pycdc' $pycdc.FullName 'exe' ; Register 'pycdc' $pycdc.FullName 'pycdc' 'cli'
  $das = Get-ChildItem $build -Recurse -Filter 'pycdas.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($das) { Shim 'pycdas' $das.FullName 'exe' ; Register 'pycdas' $das.FullName 'pycdas' 'cli' }
}

# unlicense : dépackeur DYNAMIQUE (VMProtect/Themida/Enigma) — EXÉCUTE la cible pour la
# dumper à l'OEP. À n'utiliser qu'en environnement isolé et avec autorisation explicite.
Tool 'unlicense' {
  $dest = Join-Path $Root 'unlicense'
  $exe  = Get-ChildItem $dest -Recurse -Filter 'unlicense.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not (MarkerOk $exe.FullName)) {
    $url = GHAsset 'ergrelet/unlicense' '(?i)py3\.\d+-x64\.zip$'
    $zip = Join-Path $DlDir 'unlicense.zip' ; Download $url $zip ; ExpandTo $zip $dest
    $exe = Get-ChildItem $dest -Recurse -Filter 'unlicense.exe' | Select-Object -First 1
  }
  if (-not $exe) { throw 'unlicense.exe introuvable' }
  Shim 'unlicense' $exe.FullName 'exe' ; Register 'unlicense' $exe.FullName 'unlicense' 'cli'
}

# pe-sieve : dumpeur generique de code deballe en memoire (processus en cours). Outil le plus
# proche d'un CLI pour VMProtect & co (dump de l'image en memoire ; le code virtualise reste VM).
Tool 'pe-sieve' {
  $dest = Join-Path $Root 'pe-sieve'
  $exe  = Join-Path $dest 'pe-sieve64.exe'
  if (-not (MarkerOk $exe)) {
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $url = GHAsset 'hasherezade/pe-sieve' '(?i)pe-sieve64\.exe$'
    Download $url $exe
  }
  if (-not (Test-Path $exe)) { throw 'pe-sieve64.exe introuvable' }
  Shim 'pe-sieve' $exe 'exe' ; Register 'pe-sieve' $exe 'pe-sieve' 'cli'
}

# frida : instrumentation dynamique (hooks runtime) — a utiliser EN VM sur du code malveillant.
Tool 'frida' {
  $venv = Join-Path $Root 'venv' ; $pyexe = Join-Path $venv 'Scripts\python.exe'
  if (-not (Test-Path $pyexe)) { throw 'venv absent (pyenv doit tourner avant)' }
  $exe = Join-Path $venv 'Scripts\frida.exe'
  if (-not (MarkerOk $exe)) { & $pyexe -m pip install --quiet frida-tools 2>&1 | Out-Host }
  if (-not (Test-Path $exe)) { throw 'frida introuvable apres pip install frida-tools' }
  Shim 'frida' $exe 'exe' ; Register 'frida' $exe 'frida' 'cli'
  $tr = Join-Path $venv 'Scripts\frida-trace.exe'
  if (Test-Path $tr) { Shim 'frida-trace' $tr 'exe' ; Register 'frida-trace' $tr 'frida-trace' 'cli' }
}

# ---------------------------------------------------------------------------
# ELECTRON / NODE
# ---------------------------------------------------------------------------
Tool 'asar' {
  $dest = Join-Path $Root 'asar'
  $cmd  = Join-Path $dest 'asar.cmd'        # layout d'un install npm global (-g --prefix)
  if (-not (MarkerOk $cmd)) {
    if (-not (Have 'npm')) { throw 'npm absent' }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    & cmd /c "npm install -g @electron/asar --prefix `"$dest`"" 2>&1 | Out-Host
  }
  if (-not (Test-Path $cmd)) {
    $js = Get-ChildItem $dest -Recurse -Filter 'asar.*' -ErrorAction SilentlyContinue |
          Where-Object { $_.Extension -in '.js','.mjs' } | Select-Object -First 1
    if (-not $js) { throw 'asar introuvable (fallback agent : npx --yes @electron/asar)' }
    Shim 'asar' $js.FullName 'raw' "node `"$($js.FullName)`" %*" ; Register 'asar' $js.FullName 'asar' 'cli' ; return
  }
  Shim 'asar' $cmd 'bat' ; Register 'asar' $cmd 'asar' 'cli'
}

# ---------------------------------------------------------------------------
# NATIF  (JDK 21 pour Ghidra 12, Ghidra, radare2)
# ---------------------------------------------------------------------------
# Ghidra 12 exige un JDK >= 21 ; les JDK installes (8/11/19) ne conviennent pas.
Tool 'jdk' {
  $dest = Join-Path $Root 'jdk21'
  $java = Get-ChildItem $dest -Recurse -Filter 'java.exe' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -match '\\bin\\java\.exe$' } | Select-Object -First 1
  if (-not (MarkerOk $java.FullName)) {
    $url = 'https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse'
    $zip = Join-Path $DlDir 'jdk21.zip' ; Download $url $zip ; ExpandTo $zip $dest
    $java = Get-ChildItem $dest -Recurse -Filter 'java.exe' | Where-Object { $_.FullName -match '\\bin\\java\.exe$' } | Select-Object -First 1
  }
  if (-not $java) { throw 'JDK 21 (java.exe) introuvable' }
  $jhome = Split-Path (Split-Path $java.FullName -Parent) -Parent
  Register 'jdk21' $jhome 'java' 'runtime'
}
Tool 'ghidra' {
  $dest = Join-Path $Root 'ghidra'
  $head = Get-ChildItem $dest -Recurse -Filter 'analyzeHeadless.bat' -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not (MarkerOk $head.FullName)) {
    $url = GHAsset 'NationalSecurityAgency/ghidra' 'ghidra_.*_PUBLIC_.*\.zip$'
    $zip = Join-Path $DlDir 'ghidra.zip' ; Download $url $zip ; ExpandTo $zip $dest
    $head = Get-ChildItem $dest -Recurse -Filter 'analyzeHeadless.bat' | Select-Object -First 1
  }
  if (-not $head) { throw 'analyzeHeadless.bat introuvable' }
  Shim 'ghidra-headless' $head.FullName 'bat' ; Register 'ghidra' $head.FullName 'ghidra-headless' 'cli'
}

Tool 'radare2' {
  $dest = Join-Path $Root 'radare2'
  $exe  = Get-ChildItem $dest -Recurse -Filter 'radare2.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not (MarkerOk $exe.FullName)) {
    $hdr = @{ 'User-Agent' = 'mze-re-setup' }
    $rel = Invoke-RestMethod 'https://api.github.com/repos/radareorg/radare2/releases/latest' -Headers $hdr -TimeoutSec 60
    $a = $rel.assets | Where-Object { $_.name -match '(?i)^radare2-\d+\.\d+\.\d+-w64\.zip$' } | Select-Object -First 1
    if (-not $a) { $a = $rel.assets | Where-Object { $_.name -match '(?i)-w64\.zip$' -and $_.name -notmatch '(?i)blob|static' } | Select-Object -First 1 }
    if (-not $a) { throw 'asset radare2 w64 introuvable' }
    $zip = Join-Path $DlDir 'radare2.zip' ; Download $a.browser_download_url $zip ; ExpandTo $zip $dest
    $exe = Get-ChildItem $dest -Recurse -Filter 'radare2.exe' | Select-Object -First 1
  }
  if (-not $exe) { throw 'radare2.exe introuvable' }
  $rbin = Split-Path $exe.FullName -Parent
  Shim 'r2' $exe.FullName 'exe'
  foreach ($t in 'radare2','rabin2','rafind2','rax2','radiff2','ragg2') {
    $e = Join-Path $rbin "$t.exe"
    if (Test-Path $e) { Shim $t $e 'exe' }
  }
  Register 'radare2' $exe.FullName 'r2' 'cli'
}

# retdec : plus de build Windows officiel (>= v5.0, v4.0 retiree). Ghidra assure la
# decompilation native ; retdec reste optionnel. Marque SKIP sans echouer.
if (ShouldRun 'retdec') {
  $script:Results['retdec'] = 'SKIP (optionnel, pas de build Windows ; Ghidra prend le relais)'
  Warn 'retdec : optionnel, indisponible sous Windows — Ghidra couvre la decompilation native'
}

# ---------------------------------------------------------------------------
# GO
# ---------------------------------------------------------------------------
Tool 'redress' {
  $dest = Join-Path $Root 'redress'
  $exe  = Join-Path $dest 'redress.exe'
  if (-not (MarkerOk $exe)) {
    try {
      $url = GHAsset 'goretk/redress' '(?i)windows.*\.(zip|tar\.gz)$'
      New-Item -ItemType Directory -Force -Path $dest | Out-Null
      if ($url -match '(?i)\.tar\.gz$') {
        $f = Join-Path $DlDir 'redress.tgz' ; Download $url $f ; & tar -xzf $f -C $dest
      } else {
        $zip = Join-Path $DlDir 'redress.zip' ; Download $url $zip ; ExpandTo $zip $dest
      }
      $rf = Get-ChildItem $dest -Recurse -Filter 'redress.exe' | Select-Object -First 1
      if ($rf) { $exe = $rf.FullName }
    } catch {
      # fallback : go install (peut echouer si Go trop ancien)
      if (-not (Have 'go')) { throw "release Windows absente et go absent ($($_.Exception.Message))" }
      $env:GOBIN = $dest
      & go install github.com/goretk/redress@latest 2>&1 | Out-Host
    }
  }
  if (-not (Test-Path $exe)) { throw 'redress.exe introuvable' }
  Shim 'redress' $exe 'exe' ; Register 'redress' $exe 'redress' 'cli'
}

# ---------------------------------------------------------------------------
# PATH + manifeste + env.ps1
# ---------------------------------------------------------------------------
if (-not $NoPath) {
  $cur = [Environment]::GetEnvironmentVariable('Path','User')
  if ($cur -notmatch [Regex]::Escape($BinDir)) {
    [Environment]::SetEnvironmentVariable('Path', ($cur.TrimEnd(';') + ';' + $BinDir), 'User')
    Good "PATH utilisateur += $BinDir  (rouvrir le terminal pour effet global)"
  }
  $env:Path = $env:Path.TrimEnd(';') + ';' + $BinDir
}

# Fusion avec le manifeste existant : un run -Only n'efface pas les autres outils.
$mf = Join-Path $Root 'tools.json'
$mergedTools = [ordered]@{}
if (Test-Path $mf) {
  try {
    $existing = Get-Content $mf -Raw | ConvertFrom-Json
    if ($existing -and $existing.tools) {
      foreach ($p in $existing.tools.PSObject.Properties) { $mergedTools[$p.Name] = $p.Value }
    }
  } catch {}
}
foreach ($k in $script:Manifest.Keys) { $mergedTools[$k] = $script:Manifest[$k] }
$manifestObj = [ordered]@{
  root      = $Root
  bin       = $BinDir
  generated = (Get-Date).ToString('o')
  tools     = $mergedTools
}
$manifestObj | ConvertTo-Json -Depth 6 | Set-Content -Path $mf -Encoding utf8

# env.ps1 : dot-source pour avoir le PATH dans une session
@"
# Genere par install.ps1 — dot-source : . '$Root\env.ps1'
`$env:Path = '$BinDir;' + `$env:Path
"@ | Set-Content -Path (Join-Path $Root 'env.ps1') -Encoding utf8

# ---------------------------------------------------------------------------
# RESUME
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "================= RESUME INSTALLATION =================" -ForegroundColor Magenta
$script:Results.GetEnumerator() | ForEach-Object {
  $c = if ($_.Value -eq 'OK') {'Green'} elseif ($_.Value -like 'SKIP*') {'DarkGray'} else {'Yellow'}
  Write-Host ("  {0,-14} {1}" -f $_.Key, $_.Value) -ForegroundColor $c
}
Write-Host "======================================================" -ForegroundColor Magenta
Write-Host "Manifeste : $Root\tools.json"
Write-Host "Shims     : $BinDir"
Write-Host "Log       : $LogDir\install-$stamp.log"

Stop-Transcript | Out-Null

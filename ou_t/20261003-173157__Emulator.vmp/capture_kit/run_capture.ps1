<#
  run_capture.ps1 — capture du trafic C2 du loader Immortal, EN VM ISOLEE UNIQUEMENT.
  PowerShell ADMIN requis (import CA + proxy systeme).

  Exemple :
    powershell -ExecutionPolicy Bypass -File run_capture.ps1 `
      -LoaderPath .\Emulator.vmp.exe -LicenseKey EMU-XXXX-XXXX-XXXX-XXXX -RunSeconds 40
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$LoaderPath,
  [string]$LicenseKey = "",
  [int]$Port = 8080,
  [int]$RunSeconds = 40
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$cap  = Join-Path $here 'capture'
New-Item -ItemType Directory -Force -Path $cap | Out-Null

# Garde-fou : refuser de tourner hors d'un contexte manifestement isole.
Write-Host "!!! Ce script fait TOURNER un malware potentiel. VM jetable + reseau isole UNIQUEMENT." -ForegroundColor Red
Write-Host "    Ctrl+C maintenant si ce n'est pas le cas. Pause 8s..." -ForegroundColor Yellow
Start-Sleep -Seconds 8

$mitmdump = (Get-Command mitmdump -ErrorAction SilentlyContinue).Source
if (-not $mitmdump) { throw "mitmdump absent : pip install mitmproxy" }

# 1) Generer le CA mitmproxy (1er lancement cree ~/.mitmproxy) puis l'importer dans Root
$caDir = Join-Path $env:USERPROFILE '.mitmproxy'
if (-not (Test-Path (Join-Path $caDir 'mitmproxy-ca-cert.cer'))) {
  Write-Host "[*] Generation du CA mitmproxy..."
  $p = Start-Process -FilePath $mitmdump -ArgumentList '--version' -PassThru -WindowStyle Hidden
  Start-Sleep -Seconds 4; try { $p | Stop-Process -Force } catch {}
}
$cer = Join-Path $caDir 'mitmproxy-ca-cert.cer'
if (Test-Path $cer) { & certutil -addstore -f Root "$cer" | Out-Null; Write-Host "[*] CA importe dans Root" }

# 2) Proxy systeme (WinINET)
$reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$oldServer = (Get-ItemProperty $reg -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
$oldEnable = (Get-ItemProperty $reg -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable
Set-ItemProperty $reg -Name ProxyServer -Value "127.0.0.1:$Port"
Set-ItemProperty $reg -Name ProxyEnable -Value 1
Write-Host "[*] Proxy systeme -> 127.0.0.1:$Port"

$mitm = $null; $loader = $null
try {
  # 3) Demarrer mitmdump avec l'addon
  $addon = Join-Path $here 'mitm_addon.py'
  $flows = Join-Path $cap 'flows.mitm'
  $mitm = Start-Process -FilePath $mitmdump `
    -ArgumentList @('-p', "$Port", '-s', "`"$addon`"", '-w', "`"$flows`"", '--set', 'block_global=false') `
    -WorkingDirectory $here -PassThru -WindowStyle Minimized
  Start-Sleep -Seconds 3
  Write-Host "[*] mitmdump PID=$($mitm.Id)"

  # 4) Lancer le loader (avec la license key si l'UI/args l'acceptent)
  Write-Host "[*] Lancement du loader ($RunSeconds s)..."
  $args = @()
  if ($LicenseKey) { $args += $LicenseKey }   # adapter si la cle se saisit dans l'UI
  $loader = Start-Process -FilePath $LoaderPath -ArgumentList $args -PassThru -WindowStyle Normal
  Start-Sleep -Seconds $RunSeconds
}
finally {
  # 5) Tout arreter + restaurer
  if ($loader) { cmd /c "taskkill /PID $($loader.Id) /T /F" 2>$null | Out-Null }
  if ($mitm)   { cmd /c "taskkill /PID $($mitm.Id) /T /F" 2>$null | Out-Null }
  if ($null -ne $oldEnable) { Set-ItemProperty $reg -Name ProxyEnable -Value $oldEnable } else { Set-ItemProperty $reg -Name ProxyEnable -Value 0 }
  if ($oldServer) { Set-ItemProperty $reg -Name ProxyServer -Value $oldServer }
  & certutil -delstore Root "mitmproxy" 2>$null | Out-Null
  Write-Host "[*] Proxy restaure, CA retire."
}

Write-Host "`n=== Capture ($cap) ==="
Get-ChildItem $cap -Recurse | Select-Object Name, Length | Format-Table -AutoSize | Out-String | Write-Host
Write-Host "Rejouer : mitmweb -r `"$(Join-Path $cap 'flows.mitm')`""

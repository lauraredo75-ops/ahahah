<#
  doctor.ps1 — diagnostic santé de la toolchain RE + auto-réparation.
  Vérifie chaque outil du manifeste (présence, architecture PE, intégrité jar).
  -Fix : réinstalle les outils cassés/absents via install.ps1 -Only <nom>.

  Exemples :
    powershell -ExecutionPolicy Bypass -File tools\doctor.ps1
    powershell -ExecutionPolicy Bypass -File tools\doctor.ps1 -Fix
#>
[CmdletBinding()]
param(
  [string]$Root = 'D:\re-tools',
  [switch]$Fix
)
$ErrorActionPreference = 'Continue'
$HOST_MACHINE = 0x8664   # x64

function Get-PEMachine([string]$p) {
  try {
    $fs = [IO.File]::OpenRead($p); $br = New-Object IO.BinaryReader($fs)
    $fs.Seek(0x3C,'Begin') | Out-Null; $peoff = $br.ReadInt32()
    $fs.Seek($peoff,'Begin') | Out-Null; $sig = $br.ReadUInt32()      # 'PE\0\0' = 0x4550
    if ($sig -ne 0x00004550) { $br.Close(); $fs.Close(); return $null }
    $m = $br.ReadUInt16(); $br.Close(); $fs.Close(); return $m
  } catch { return $null }
}
function ArchName([int]$m) {
  switch ($m) { 0x8664 {'x64'} 0x14c {'x86'} 0xAA64 {'ARM64'} 0x1c0 {'ARM'} default {('0x{0:x}' -f $m)} }
}
function Get-JarOk([string]$p) {
  try { $b = [byte[]](Get-Content -LiteralPath $p -Encoding Byte -TotalCount 2); return ($b[0] -eq 0x50 -and $b[1] -eq 0x4B) } catch { return $false }
}

$mf = Join-Path $Root 'tools.json'
if (-not (Test-Path $mf)) { Write-Host "Manifeste absent : $mf - lance d'abord tools\install.ps1" -ForegroundColor Red; exit 1 }
$man = Get-Content $mf -Raw | ConvertFrom-Json

$rows = @(); $broken = @()
foreach ($p in $man.tools.PSObject.Properties) {
  $name = $p.Name; $t = $p.Value; $path = $t.path; $kind = $t.kind
  $state = 'OK'; $detail = ''
  if (-not (Test-Path $path)) {
    $state = 'MISSING'; $detail = 'chemin inexistant'
  }
  elseif ($path -match '\.exe$') {
    $m = Get-PEMachine $path
    if ($m -eq 0xAA64) { $state = 'BROKEN'; $detail = "architecture ARM64 (incompatible x64)" }
    elseif ($m -eq $null) { $state = 'WARN'; $detail = 'pas un PE reconnu' }
    else { $detail = ArchName $m }
  }
  elseif ($path -match '\.jar$') {
    if (-not (Get-JarOk $path)) { $state = 'BROKEN'; $detail = 'jar invalide (pas de PK)' } else { $detail = 'jar' }
  }
  elseif ($path -match '\.(bat|cmd)$') { $detail = 'script' }

  $rows += [pscustomobject]@{ Outil=$name; Etat=$state; Detail=$detail; Chemin=$path }
  if ($state -in @('BROKEN','MISSING')) { $broken += $name }
}

Write-Host "`n=== DOCTOR - sante toolchain ($($rows.Count) outils) ===" -ForegroundColor Cyan
$rows | ForEach-Object {
  $c = switch ($_.Etat) { 'OK' {'Green'} 'WARN' {'Yellow'} default {'Red'} }
  Write-Host ("  {0,-12} {1,-8} {2}" -f $_.Outil, $_.Etat, $_.Detail) -ForegroundColor $c
}

if ($broken.Count -eq 0) {
  Write-Host "`nTout est opérationnel." -ForegroundColor Green
} else {
  Write-Host "`nÀ réparer : $($broken -join ', ')" -ForegroundColor Yellow
  if ($Fix) {
    $only = $broken -join ','
    Write-Host "Réparation : install.ps1 -Only $only -Force ..." -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'install.ps1') -Only $only -Force
    Write-Host "Relance 'doctor.ps1' pour revérifier." -ForegroundColor Cyan
  } else {
    Write-Host "Lance avec -Fix pour réinstaller automatiquement." -ForegroundColor Yellow
  }
}

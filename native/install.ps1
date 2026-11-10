# install.ps1 — сборка и установка native host FLICKER VPN (Windows).
# Запуск: powershell -ExecutionPolicy Bypass -File native\install.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Error "Нужен Go (1.26+) в PATH"
}

Write-Host "Сборка flicker-host.exe..."
go build -tags "with_utls with_gvisor" -o flicker-host.exe ./cmd/flicker-host

$installDir = Join-Path $env:LOCALAPPDATA "flicker-vpn"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
$binPath = Join-Path $installDir "flicker-host.exe"
Copy-Item -Force flicker-host.exe $binPath
Write-Host "Бинарник: $binPath"

$manifestDir = Join-Path $installDir "nm"
New-Item -ItemType Directory -Force -Path $manifestDir | Out-Null
$manifestPath = Join-Path $manifestDir "com.flicker.vpn.json"

$manifest = @{
    name = "com.flicker.vpn"
    description = "FLICKER VPN native tunnel (HY2/TUIC)"
    path = $binPath
    type = "stdio"
    allowed_extensions = @("flicker-vpn@local.dev")
} | ConvertTo-Json
Set-Content -Path $manifestPath -Value $manifest -Encoding UTF8

# Регистрация для Firefox через реестр HKCU
$regPath = "HKCU:\Software\Mozilla\NativeMessagingHosts\com.flicker.vpn"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "(default)" -Value $manifestPath
Write-Host "Реестр: $regPath -> $manifestPath"

Write-Host ""
Write-Host "Готово. Перезапустите Firefox и загрузите расширение через about:debugging."


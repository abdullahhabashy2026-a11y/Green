$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    python -m venv .venv
}

.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install pyinstaller

.\.venv\Scripts\python.exe -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --uac-admin `
    --add-data "..\server\blocklists\adult.txt;blocklists" `
    --add-data "..\server\blocklists\custom.txt;blocklists" `
    --name GreenAgent `
    agent_gui.pyw

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed. Close any running GreenAgent.exe window/tray process, then run this build script again."
}

Write-Host ""
Write-Host "Build complete:"
Write-Host "$Root\dist\GreenAgent.exe"

# Sets up a Python virtualenv and installs development dependencies
# Usage: Open PowerShell, run: .\scripts\setup_dev_env.ps1

$ErrorActionPreference = 'Stop'

if (-Not (Test-Path -Path '.venv')) {
    python -m venv .venv
    Write-Host "Created virtual environment at .\.venv"
} else {
    Write-Host "Virtual environment .\.venv already exists"
}

# Activate and upgrade pip, then install project and dev deps
Write-Host "To finish setup, run these commands in PowerShell:"
Write-Host "    .\\.venv\\Scripts\\Activate.ps1"
Write-Host "    python -m pip install --upgrade pip"
Write-Host "    pip install -e .[dev]"
Write-Host "Then run: pytest -q"

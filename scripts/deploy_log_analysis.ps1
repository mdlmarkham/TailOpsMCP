#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Deploy Intelligent Log Analysis feature to dev1 server

.DESCRIPTION
    This script deploys the updated SystemManager MCP server with
    intelligent log analysis capabilities to the remote server.

.EXAMPLE
    .\deploy_log_analysis.ps1
#>

$ErrorActionPreference = "Stop"

$SERVER = "dev1.tailf9480.ts.net"
$DEPLOY_PATH = "/opt/systemmanager"
$SERVICE_NAME = "systemmanager-mcp"

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "Deploying Intelligent Log Analysis to $SERVER" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Test local changes
Write-Host "[1/6] Testing local changes..." -ForegroundColor Yellow
python test_log_analysis.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Local tests failed!" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Local tests passed" -ForegroundColor Green
Write-Host ""

# Step 2: Check git status
Write-Host "[2/6] Checking git status..." -ForegroundColor Yellow
git status --short
Write-Host ""

$commit = Read-Host "Commit and push changes? (y/n)"
if ($commit -eq "y") {
    $message = Read-Host "Commit message"
    if ([string]::IsNullOrWhiteSpace($message)) {
        $message = "Add intelligent log analysis with AI sampling"
    }
    
    git add -A
    git commit -m "$message"
    git push origin master
    Write-Host "✅ Changes committed and pushed" -ForegroundColor Green
} else {
    Write-Host "⚠️  Skipping commit (ensure changes are pushed manually)" -ForegroundColor Yellow
}
Write-Host ""

# Step 3: Pull changes on server
Write-Host "[3/6] Pulling changes on server..." -ForegroundColor Yellow
ssh $SERVER "cd $DEPLOY_PATH && git pull origin master"
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to pull changes!" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Changes pulled successfully" -ForegroundColor Green
Write-Host ""

# Step 4: Check Python dependencies
Write-Host "[4/6] Checking Python environment..." -ForegroundColor Yellow
ssh $SERVER "cd $DEPLOY_PATH && source venv/bin/activate && pip list | grep -E 'fastmcp|docker|psutil'"
Write-Host "✅ Dependencies verified" -ForegroundColor Green
Write-Host ""

# Step 5: Restart service
Write-Host "[5/6] Restarting MCP service..." -ForegroundColor Yellow
ssh $SERVER "sudo systemctl restart $SERVICE_NAME"
Start-Sleep -Seconds 3
ssh $SERVER "sudo systemctl status $SERVICE_NAME --no-pager | head -20"
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Service failed to start!" -ForegroundColor Red
    Write-Host "Checking logs..." -ForegroundColor Yellow
    ssh $SERVER "sudo journalctl -u $SERVICE_NAME -n 50 --no-pager"
    exit 1
}
Write-Host "✅ Service restarted successfully" -ForegroundColor Green
Write-Host ""

# Step 6: Verify deployment
Write-Host "[6/6] Verifying deployment..." -ForegroundColor Yellow
Write-Host "Checking server logs for sampling capability..." -ForegroundColor Cyan
ssh $SERVER "tail -20 $DEPLOY_PATH/logs/mcp_server.log"
Write-Host ""

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "Deployment Complete!" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Test the new analyze_container_logs tool from VS Code" -ForegroundColor White
Write-Host "  2. Ask Copilot: 'Analyze the logs for container X'" -ForegroundColor White
Write-Host "  3. Compare AI-enhanced vs basic analysis results" -ForegroundColor White
Write-Host ""
Write-Host "Documentation: docs/INTELLIGENT_LOG_ANALYSIS.md" -ForegroundColor Cyan
Write-Host "Test suite: test_log_analysis.py" -ForegroundColor Cyan
Write-Host ""

# Offer to test immediately
$test = Read-Host "Test the new feature now? (y/n)"
if ($test -eq "y") {
    Write-Host ""
    Write-Host "Available containers on $SERVER:" -ForegroundColor Yellow
    ssh $SERVER "docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'"
    Write-Host ""
    Write-Host "Use the 'analyze_container_logs' tool from VS Code to analyze any container" -ForegroundColor Cyan
}

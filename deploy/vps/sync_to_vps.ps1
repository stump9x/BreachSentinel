# Sync local BreachSentinel sources to the VPS using the same SSH key as NewsCrawler.
# No password prompts when Host "breachsentinel" is configured in ~/.ssh/config.
#
# Usage (from project root):
#   powershell -File deploy/vps/sync_to_vps.ps1
#   powershell -File deploy/vps/sync_to_vps.ps1 -Optimize
#   powershell -File deploy/vps/sync_to_vps.ps1 -Remote "docker compose -f docker-compose.yml -f docker-compose.vps.yml ps"
param(
  [switch]$Optimize,
  [string]$Remote = "",
  [string]$HostName = "breachsentinel",
  [string]$RemoteDir = "~/BreachSentinel"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

function Invoke-Vps([string]$Cmd) {
  ssh -o BatchMode=yes -o ConnectTimeout=20 $HostName $Cmd
  if ($LASTEXITCODE -ne 0) { throw "SSH command failed: $Cmd" }
}

Write-Host ">> SSH host: $HostName"
Invoke-Vps "mkdir -p $RemoteDir"

$pairs = @(
  @{ Local = "docker-compose.yml"; Remote = "$RemoteDir/" },
  @{ Local = "docker-compose.vps.yml"; Remote = "$RemoteDir/" },
  @{ Local = "docker-compose.prod.yml"; Remote = "$RemoteDir/" },
  @{ Local = ".env.example"; Remote = "$RemoteDir/" },
  @{ Local = "README.md"; Remote = "$RemoteDir/" },
  @{ Local = "backend\apps\integrations\ai\translate.py"; Remote = "$RemoteDir/backend/apps/integrations/ai/" },
  @{ Local = "backend\apps\integrations\ai\summary_translate.py"; Remote = "$RemoteDir/backend/apps/integrations/ai/" },
  @{ Local = "backend\apps\integrations\ai\groq_pool.py"; Remote = "$RemoteDir/backend/apps/integrations/ai/" },
  @{ Local = "backend\apps\integrations\tests\test_title_translate.py"; Remote = "$RemoteDir/backend/apps/integrations/tests/" },
  @{ Local = "backend\apps\integrations\tests\test_groq_pool.py"; Remote = "$RemoteDir/backend/apps/integrations/tests/" },
  @{ Local = "backend\config\settings.py"; Remote = "$RemoteDir/backend/config/" },
  @{ Local = "backend\apps\integrations\ai\clients.py"; Remote = "$RemoteDir/backend/apps/integrations/ai/" },
  @{ Local = "backend\apps\integrations\views.py"; Remote = "$RemoteDir/backend/apps/integrations/" },
  @{ Local = "backend\apps\workers\services.py"; Remote = "$RemoteDir/backend/apps/workers/" },
  @{ Local = "backend\apps\workers\geography.py"; Remote = "$RemoteDir/backend/apps/workers/" },
  @{ Local = "backend\apps\workers\models.py"; Remote = "$RemoteDir/backend/apps/workers/" },
  @{ Local = "backend\apps\workers\log_scanner.py"; Remote = "$RemoteDir/backend/apps/workers/" },
  @{ Local = "backend\apps\workers\log_scan_views.py"; Remote = "$RemoteDir/backend/apps/workers/" },
  @{ Local = "backend\apps\workers\urls.py"; Remote = "$RemoteDir/backend/apps/workers/" },
  @{ Local = "backend\apps\workers\tasks.py"; Remote = "$RemoteDir/backend/apps/workers/" },
  @{ Local = "backend\apps\workers\admin.py"; Remote = "$RemoteDir/backend/apps/workers/" },
  @{ Local = "backend\apps\workers\migrations\__init__.py"; Remote = "$RemoteDir/backend/apps/workers/migrations/" },
  @{ Local = "backend\apps\workers\migrations\0001_log_scanner.py"; Remote = "$RemoteDir/backend/apps/workers/migrations/" },
  @{ Local = "backend\apps\workers\tests\test_log_scanner.py"; Remote = "$RemoteDir/backend/apps/workers/tests/" },
  @{ Local = "backend\apps\workers\tests\test_geography_tags.py"; Remote = "$RemoteDir/backend/apps/workers/tests/" },
  @{ Local = "backend\apps\workers\tests\test_precise_tags.py"; Remote = "$RemoteDir/backend/apps/workers/tests/" },
  @{ Local = "backend\apps\intel\management\commands\retag_wire_geography.py"; Remote = "$RemoteDir/backend/apps/intel/management/commands/" },
  @{ Local = "backend\apps\intel\filters.py"; Remote = "$RemoteDir/backend/apps/intel/" },
  @{ Local = "backend\apps\intel\views.py"; Remote = "$RemoteDir/backend/apps/intel/" },
  @{ Local = "backend\apps\intel\tests\test_vietnam_wire_window.py"; Remote = "$RemoteDir/backend/apps/intel/tests/" },
  @{ Local = "backend\config\settings.py"; Remote = "$RemoteDir/backend/config/" },
  @{ Local = "frontend\src\pages\ThreatsPage.jsx"; Remote = "$RemoteDir/frontend/src/pages/" },
  @{ Local = "frontend\src\pages\LogsScannerPage.jsx"; Remote = "$RemoteDir/frontend/src/pages/" },
  @{ Local = "frontend\src\App.jsx"; Remote = "$RemoteDir/frontend/src/" },
  @{ Local = "frontend\src\layout\AppShell.jsx"; Remote = "$RemoteDir/frontend/src/layout/" },
  @{ Local = "frontend\src\api\client.js"; Remote = "$RemoteDir/frontend/src/api/" },
  @{ Local = "frontend\src\auth\AuthContext.jsx"; Remote = "$RemoteDir/frontend/src/auth/" },
  @{ Local = "frontend\src\utils\dateTime.js"; Remote = "$RemoteDir/frontend/src/utils/" },
  @{ Local = "frontend\src\utils\dateTime.test.js"; Remote = "$RemoteDir/frontend/src/utils/" },
  @{ Local = "deploy\vps\sync_groq_keys_from_newscrawler.sh"; Remote = "$RemoteDir/deploy/vps/" },
  @{ Local = "frontend\nginx.conf"; Remote = "$RemoteDir/frontend/" },
  @{ Local = "deploy\vps\optimize_vps.sh"; Remote = "$RemoteDir/deploy/vps/" },
  @{ Local = "deploy\vps\deploy.sh"; Remote = "$RemoteDir/deploy/vps/" },
  @{ Local = "deploy\vps\bootstrap_data.sh"; Remote = "$RemoteDir/deploy/vps/" },
  @{ Local = "deploy\vps\restore_from_local.sh"; Remote = "$RemoteDir/deploy/vps/" },
  @{ Local = "deploy\vps\verify_vps.sh"; Remote = "$RemoteDir/deploy/vps/" },
  @{ Local = "deploy\vps\sync_to_vps.sh"; Remote = "$RemoteDir/deploy/vps/" },
  @{ Local = "deploy\vps\sync_to_vps.ps1"; Remote = "$RemoteDir/deploy/vps/" }
)

Write-Host ">> Syncing files to ${HostName}:${RemoteDir}"
foreach ($p in $pairs) {
  $src = Join-Path $Root $p.Local
  if (-not (Test-Path $src)) {
    Write-Host "   skip missing $($p.Local)"
    continue
  }
  scp -o BatchMode=yes $src "${HostName}:$($p.Remote)"
  if ($LASTEXITCODE -ne 0) { throw "scp failed for $($p.Local)" }
}

Invoke-Vps "sed -i 's/\r`$//' $RemoteDir/deploy/vps/*.sh && chmod +x $RemoteDir/deploy/vps/*.sh"

if ($Optimize) {
  Write-Host ">> Running optimize_vps.sh on VPS"
  Invoke-Vps "cd $RemoteDir && bash deploy/vps/optimize_vps.sh"
}

if ($Remote) {
  Write-Host ">> Remote: $Remote"
  Invoke-Vps "cd $RemoteDir && $Remote"
}

Write-Host "Done."

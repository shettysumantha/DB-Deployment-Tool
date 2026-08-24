$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$TableFolder = Join-Path $Root "Tables"

$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputFile = Join-Path $Root "Deploy_Tables_$TimeStamp.sql"

if (!(Test-Path $TableFolder)) {
    throw "Tables folder not found."
}

$tableFiles = Get-ChildItem $TableFolder -File | Sort-Object Name

if ($tableFiles.Count -eq 0) {
    throw "No table scripts found."
}

New-Item $OutputFile -ItemType File -Force | Out-Null

@"
-- ==========================================
-- TABLE DEPLOYMENT SCRIPT
-- Generated : $(Get-Date)
-- ==========================================

"@ | Set-Content $OutputFile

Write-Host ""
Write-Host "Tables Included"
Write-Host "---------------"

foreach($file in $tableFiles)
{
    Write-Host $file.Name

    Add-Content $OutputFile ""
    Add-Content $OutputFile "-- ===================================="
    Add-Content $OutputFile "-- $($file.Name)"
    Add-Content $OutputFile "-- ===================================="

    Get-Content $file.FullName | Add-Content $OutputFile
}

Add-Content $OutputFile ""
# Add-Content $OutputFile "COMMIT;"

Write-Host ""
Write-Host "Generated:"
Write-Host $OutputFile -ForegroundColor Green
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$FunctionFolder = Join-Path $Root "Functions"

$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputFile = Join-Path $Root "Deploy_Functions_$TimeStamp.sql"

if (!(Test-Path $FunctionFolder)) {
    throw "Functions folder not found."
}

$functionFiles = Get-ChildItem $FunctionFolder -File | Sort-Object Name

if ($functionFiles.Count -eq 0) {
    throw "No function scripts found."
}

New-Item $OutputFile -ItemType File -Force | Out-Null

@"
-- ==========================================
-- FUNCTION DEPLOYMENT SCRIPT
-- Generated : $(Get-Date)
-- ==========================================


"@ | Set-Content $OutputFile

Write-Host ""
Write-Host "Functions Included"
Write-Host "------------------"

foreach($file in $functionFiles)
{
    Write-Host $file.Name

    Add-Content $OutputFile ""
    Add-Content $OutputFile "-- ===================================="
    Add-Content $OutputFile "-- $($file.Name)"
    Add-Content $OutputFile "-- ===================================="

    Get-Content $file.FullName | Add-Content $OutputFile
}

Add-Content $OutputFile ""
#Add-Content $OutputFile "COMMIT;"

Write-Host ""
Write-Host "Generated:"
Write-Host $OutputFile -ForegroundColor Green
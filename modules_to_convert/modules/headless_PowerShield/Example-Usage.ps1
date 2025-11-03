<#
.SYNOPSIS
    Example demonstrating how to use the PowerShield Headless Module
    
.DESCRIPTION
    This script shows common usage patterns for embedding PowerShield
    into your own tools and workflows.
#>

# Import the headless module
Import-Module "$PSScriptRoot\HeadlessPowerShield.psm1" -Force

Write-Host "PowerShield Headless Module - Usage Examples" -ForegroundColor Cyan
Write-Host "=" * 50

# Example 1: Basic Analysis
Write-Host "`n[Example 1] Basic File Analysis" -ForegroundColor Yellow
$testScript = "$PSScriptRoot\..\tests\TestScripts\powershell\insecure-hash.ps1"

if (Test-Path $testScript) {
    $result = Invoke-Analysis -Path $testScript
    
    Write-Host "  File: $($result.AnalyzedPath)"
    Write-Host "  Violations Found: $($result.Summary.TotalViolations)"
    
    if ($result.Summary.TotalViolations -gt 0) {
        Write-Host "`n  Top Violation:"
        $topViolation = $result.Results[0].Violations[0]
        Write-Host "    Rule: $($topViolation.RuleId)" -ForegroundColor Red
        Write-Host "    Severity: $($topViolation.Severity)"
        Write-Host "    Message: $($topViolation.Message)"
        Write-Host "    Location: Line $($topViolation.LineNumber), Column $($topViolation.ColumnNumber)"
    }
}
else {
    Write-Host "  Test script not found, skipping..." -ForegroundColor Gray
}

# Example 2: Initialize with Configuration
Write-Host "`n[Example 2] Custom Analyzer Configuration" -ForegroundColor Yellow

$analyzer = Initialize-PowerShield
Set-Configuration -Analyzer $analyzer -MaxFileSize 20MB -AnalysisTimeout 60

$rules = Get-SecurityRules -Analyzer $analyzer
Write-Host "  Total Rules Loaded: $($rules.Count)"
Write-Host "  Critical Rules: $(($rules | Where-Object Severity -eq 'Critical').Count)"
Write-Host "  High Rules: $(($rules | Where-Object Severity -eq 'High').Count)"
Write-Host "  Medium Rules: $(($rules | Where-Object Severity -eq 'Medium').Count)"

# Example 3: Workspace Analysis
Write-Host "`n[Example 3] Workspace Analysis" -ForegroundColor Yellow
$testWorkspace = "$PSScriptRoot\..\tests\TestScripts\powershell"

if (Test-Path $testWorkspace) {
    $workspaceResult = Invoke-Analysis -Path $testWorkspace -Analyzer $analyzer
    
    Write-Host "  Workspace: $($workspaceResult.AnalyzedPath)"
    Write-Host "  Files Analyzed: $($workspaceResult.Summary.TotalFiles)"
    Write-Host "  Files with Issues: $($workspaceResult.Summary.FilesWithViolations)"
    Write-Host "  Total Violations: $($workspaceResult.Summary.TotalViolations)"
    
    Write-Host "`n  Violations by Severity:"
    $workspaceResult.Summary.ViolationsBySeverity.GetEnumerator() | Sort-Object Name | ForEach-Object {
        Write-Host "    $($_.Key): $($_.Value)"
    }
}
else {
    Write-Host "  Test workspace not found, skipping..." -ForegroundColor Gray
}

# Example 4: Export Results
Write-Host "`n[Example 4] Exporting Results" -ForegroundColor Yellow

if ($workspaceResult) {
    # Export to JSON
    $jsonPath = "$PSScriptRoot\example-results.json"
    $workspaceResult | Export-AnalysisResult -Format JSON -OutputPath $jsonPath
    Write-Host "  JSON exported to: $jsonPath"
    
    # Export to SARIF
    $sarifPath = "$PSScriptRoot\example-results.sarif"
    $workspaceResult | Export-AnalysisResult -Format SARIF -OutputPath $sarifPath
    Write-Host "  SARIF exported to: $sarifPath"
    
    # Display as CSV (in console)
    Write-Host "`n  Sample CSV Output:"
    $csvOutput = $workspaceResult | Export-AnalysisResult -Format CSV
    $csvOutput | Select-Object -First 5 | Out-String | Write-Host
}

# Example 5: Filter Rules by Severity
Write-Host "`n[Example 5] Filtering Rules" -ForegroundColor Yellow

$criticalRules = Get-SecurityRules -Analyzer $analyzer -Severity Critical
Write-Host "  Critical Rules:"
$criticalRules | Select-Object -First 3 | ForEach-Object {
    Write-Host "    - $($_.Id): $($_.Description)"
}

# Example 6: Embedding in a Function
Write-Host "`n[Example 6] Embedded Security Check Function" -ForegroundColor Yellow

function Test-ScriptSecurity {
    param(
        [Parameter(Mandatory)]
        [string]$ScriptPath,
        
        [switch]$FailOnCritical
    )
    
    $result = Invoke-Analysis -Path $ScriptPath
    $criticalCount = ($result.Results.Violations | Where-Object { $_.Severity -eq 'Critical' }).Count
    
    if ($FailOnCritical -and $criticalCount -gt 0) {
        throw "Security check failed: $criticalCount critical violations found"
    }
    
    return @{
        Passed = $criticalCount -eq 0
        CriticalViolations = $criticalCount
        TotalViolations = $result.Summary.TotalViolations
    }
}

if (Test-Path $testScript) {
    $securityCheck = Test-ScriptSecurity -ScriptPath $testScript
    Write-Host "  Security Check Result:"
    Write-Host "    Passed: $($securityCheck.Passed)"
    Write-Host "    Critical Violations: $($securityCheck.CriticalViolations)"
    Write-Host "    Total Violations: $($securityCheck.TotalViolations)"
}

Write-Host "`n" -NoNewline
Write-Host "=" * 50
Write-Host "Examples completed!" -ForegroundColor Green
Write-Host "`nClean up temporary files? (Press Enter to skip)" -ForegroundColor Gray
$cleanup = Read-Host

if ($cleanup -eq 'y' -or $cleanup -eq 'yes') {
    Remove-Item "$PSScriptRoot\example-results.json" -ErrorAction SilentlyContinue
    Remove-Item "$PSScriptRoot\example-results.sarif" -ErrorAction SilentlyContinue
    Write-Host "Temporary files removed." -ForegroundColor Green
}

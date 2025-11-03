#Requires -Version 7.0

<#
.SYNOPSIS
    Baseline management module for PowerShield
.DESCRIPTION
    Manages security baselines with versioning, comparison, and team sharing capabilities.
    Supports tracking changes over time and identifying new violations.
.NOTES
    Version: 1.0.0
    Author: PowerShield Project
#>

# Baseline version class
class BaselineVersion {
    [string]$Version
    [datetime]$CreatedAt
    [string]$CreatedBy
    [string]$Description
    [int]$TotalViolations
    [hashtable]$SeverityCounts
    [string]$FilePath
    [string]$GitCommit
    [string]$Branch
    
    BaselineVersion() {
        $this.Version = "1.0.0"
        $this.CreatedAt = Get-Date
        $this.CreatedBy = if ($env:USER) { $env:USER } elseif ($env:USERNAME) { $env:USERNAME } else { "unknown" }
        $this.Description = ""
        $this.TotalViolations = 0
        $this.SeverityCounts = @{}
        $this.FilePath = ""
        $this.GitCommit = ""
        $this.Branch = ""
    }
}

# Baseline comparison result class
class BaselineComparison {
    [object[]]$NewViolations
    [object[]]$FixedViolations
    [object[]]$UnchangedViolations
    [int]$TotalNew
    [int]$TotalFixed
    [int]$TotalUnchanged
    [hashtable]$Summary
    
    BaselineComparison() {
        $this.NewViolations = @()
        $this.FixedViolations = @()
        $this.UnchangedViolations = @()
        $this.TotalNew = 0
        $this.TotalFixed = 0
        $this.TotalUnchanged = 0
        $this.Summary = @{}
    }
}

function New-BaselineVersion {
    <#
    .SYNOPSIS
        Creates a new baseline version from analysis results
    .PARAMETER AnalysisResult
        The analysis result object
    .PARAMETER Description
        Optional description for this baseline version
    .PARAMETER OutputPath
        Path to save the baseline file (default: .powershield-baseline.json)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$AnalysisResult,
        
        [Parameter()]
        [string]$Description = "",
        
        [Parameter()]
        [string]$OutputPath = ".powershield-baseline.json"
    )
    
    $baseline = [BaselineVersion]::new()
    $baseline.Description = $Description
    $baseline.FilePath = $OutputPath
    
    # Get git info if available
    try {
        $gitCommit = git rev-parse HEAD 2>$null
        $gitBranch = git rev-parse --abbrev-ref HEAD 2>$null
        if ($gitCommit) { $baseline.GitCommit = $gitCommit.Trim() }
        if ($gitBranch) { $baseline.Branch = $gitBranch.Trim() }
    } catch {
        # Git not available or not a git repo
    }
    
    # Extract violations
    $allViolations = @()
    foreach ($fileResult in $AnalysisResult.Results) {
        if ($fileResult.Violations) {
            $allViolations += $fileResult.Violations
        }
    }
    
    $baseline.TotalViolations = $allViolations.Count
    
    # Count by severity
    $baseline.SeverityCounts = @{
        Critical = ($allViolations | Where-Object { $_.Severity -eq 'Critical' }).Count
        High = ($allViolations | Where-Object { $_.Severity -eq 'High' }).Count
        Medium = ($allViolations | Where-Object { $_.Severity -eq 'Medium' }).Count
        Low = ($allViolations | Where-Object { $_.Severity -eq 'Low' }).Count
    }
    
    # Create baseline data structure
    $baselineData = @{
        Version = $baseline.Version
        CreatedAt = $baseline.CreatedAt.ToString('yyyy-MM-ddTHH:mm:ssZ')
        CreatedBy = $baseline.CreatedBy
        Description = $baseline.Description
        GitCommit = $baseline.GitCommit
        Branch = $baseline.Branch
        TotalViolations = $baseline.TotalViolations
        SeverityCounts = $baseline.SeverityCounts
        Violations = $allViolations
        AnalysisResult = $AnalysisResult
    }
    
    # Save baseline
    $baselineData | ConvertTo-Json -Depth 20 | Out-File -FilePath $OutputPath -Encoding UTF8
    
    return $baseline
}

function Get-BaselineHistory {
    <#
    .SYNOPSIS
        Lists all baseline versions in the current directory
    .PARAMETER Directory
        Directory to search for baseline files (default: current directory)
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Directory = "."
    )
    
    $baselines = @()
    # Include hidden files with -Force parameter
    $baselineFiles = Get-ChildItem -Path $Directory -Filter "*baseline*.json" -Force -ErrorAction SilentlyContinue
    
    foreach ($file in $baselineFiles) {
        try {
            $data = Get-Content $file.FullName -Raw | ConvertFrom-Json
            
            # Handle different baseline formats
            $createdAt = if ($data.CreatedAt) { [datetime]$data.CreatedAt } else { $file.CreationTime }
            $createdBy = if ($data.CreatedBy) { $data.CreatedBy } else { "Unknown" }
            $totalViolations = if ($data.TotalViolations) { $data.TotalViolations } 
                              elseif ($data.Violations) { $data.Violations.Count }
                              elseif ($data.AnalysisResult.TotalViolations) { $data.AnalysisResult.TotalViolations }
                              else { 0 }
            
            $version = [PSCustomObject]@{
                FilePath = $file.FullName
                FileName = $file.Name
                Version = if ($data.Version) { $data.Version } else { "1.0" }
                CreatedAt = $createdAt
                CreatedBy = $createdBy
                Description = if ($data.Description) { $data.Description } else { "" }
                GitCommit = if ($data.GitCommit) { $data.GitCommit } else { "" }
                Branch = if ($data.Branch) { $data.Branch } else { "" }
                TotalViolations = $totalViolations
                SeverityCounts = if ($data.SeverityCounts) { $data.SeverityCounts } else { @{} }
            }
            $baselines += $version
        } catch {
            Write-Warning "Failed to parse baseline file: $($file.Name) - $_"
        }
    }
    
    return $baselines | Sort-Object -Property CreatedAt -Descending
}

function Compare-Baseline {
    <#
    .SYNOPSIS
        Compares current analysis results with a baseline
    .PARAMETER CurrentResult
        Current analysis result
    .PARAMETER BaselinePath
        Path to baseline file
    .PARAMETER IncludeUnchanged
        Include violations that exist in both baseline and current analysis
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$CurrentResult,
        
        [Parameter(Mandatory)]
        [string]$BaselinePath,
        
        [Parameter()]
        [switch]$IncludeUnchanged
    )
    
    if (-not (Test-Path $BaselinePath)) {
        throw "Baseline file not found: $BaselinePath"
    }
    
    $baselineData = Get-Content $BaselinePath -Raw | ConvertFrom-Json
    $comparison = [BaselineComparison]::new()
    
    # Extract current violations
    $currentViolations = @()
    foreach ($fileResult in $CurrentResult.Results) {
        if ($fileResult.Violations) {
            $currentViolations += $fileResult.Violations
        }
    }
    
    # Extract baseline violations
    $baselineViolations = @()
    if ($baselineData.Violations) {
        $baselineViolations = $baselineData.Violations
    } elseif ($baselineData.AnalysisResult.Results) {
        foreach ($fileResult in $baselineData.AnalysisResult.Results) {
            if ($fileResult.Violations) {
                $baselineViolations += $fileResult.Violations
            }
        }
    }
    
    # Find new violations
    foreach ($current in $currentViolations) {
        $found = $false
        foreach ($baseline in $baselineViolations) {
            if (Test-ViolationMatch $current $baseline) {
                $found = $true
                if ($IncludeUnchanged) {
                    $comparison.UnchangedViolations += $current
                }
                break
            }
        }
        if (-not $found) {
            $comparison.NewViolations += $current
        }
    }
    
    # Find fixed violations
    foreach ($baseline in $baselineViolations) {
        $found = $false
        foreach ($current in $currentViolations) {
            if (Test-ViolationMatch $baseline $current) {
                $found = $true
                break
            }
        }
        if (-not $found) {
            $comparison.FixedViolations += $baseline
        }
    }
    
    $comparison.TotalNew = $comparison.NewViolations.Count
    $comparison.TotalFixed = $comparison.FixedViolations.Count
    $comparison.TotalUnchanged = $comparison.UnchangedViolations.Count
    
    # Create summary
    $comparison.Summary = @{
        BaselineDate = $baselineData.CreatedAt
        BaselineVersion = $baselineData.Version
        BaselineViolations = $baselineViolations.Count
        CurrentViolations = $currentViolations.Count
        NewViolations = $comparison.TotalNew
        FixedViolations = $comparison.TotalFixed
        UnchangedViolations = $comparison.TotalUnchanged
        ChangePercentage = if ($baselineViolations.Count -gt 0) {
            [math]::Round((($comparison.TotalNew - $comparison.TotalFixed) / $baselineViolations.Count) * 100, 2)
        } else { 0 }
    }
    
    return $comparison
}

function Test-ViolationMatch {
    <#
    .SYNOPSIS
        Tests if two violations match (same issue in same location)
    #>
    param($Violation1, $Violation2)
    
    return ($Violation1.RuleId -eq $Violation2.RuleId) -and
           ($Violation1.FilePath -eq $Violation2.FilePath) -and
           ($Violation1.LineNumber -eq $Violation2.LineNumber)
}

function Export-BaselineReport {
    <#
    .SYNOPSIS
        Exports a baseline comparison report in various formats
    .PARAMETER Comparison
        Baseline comparison result
    .PARAMETER Format
        Output format (markdown, html, json)
    .PARAMETER OutputPath
        Path to save the report
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [BaselineComparison]$Comparison,
        
        [Parameter()]
        [ValidateSet('markdown', 'html', 'json')]
        [string]$Format = 'markdown',
        
        [Parameter(Mandatory)]
        [string]$OutputPath
    )
    
    switch ($Format) {
        'markdown' {
            $report = Generate-MarkdownReport -Comparison $Comparison
            $report | Out-File -FilePath $OutputPath -Encoding UTF8
        }
        'json' {
            $Comparison | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
        }
        'html' {
            $mdReport = Generate-MarkdownReport -Comparison $Comparison
            # Simple HTML wrapper
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Baseline Comparison Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        pre { background-color: #f4f4f4; padding: 10px; border-radius: 5px; }
        .new { color: #d73a49; }
        .fixed { color: #28a745; }
    </style>
</head>
<body>
    <pre>$mdReport</pre>
</body>
</html>
"@
            $html | Out-File -FilePath $OutputPath -Encoding UTF8
        }
    }
}

function Generate-MarkdownReport {
    param([BaselineComparison]$Comparison)
    
    $report = @"
# PowerShield Baseline Comparison Report

## Summary

- **Baseline Date**: $($Comparison.Summary.BaselineDate)
- **Baseline Version**: $($Comparison.Summary.BaselineVersion)
- **Baseline Violations**: $($Comparison.Summary.BaselineViolations)
- **Current Violations**: $($Comparison.Summary.CurrentViolations)
- **Change**: $($Comparison.Summary.ChangePercentage)%

## Changes

### ✓ Fixed Issues: $($Comparison.TotalFixed)

"@

    if ($Comparison.TotalFixed -gt 0) {
        foreach ($violation in $Comparison.FixedViolations | Select-Object -First 20) {
            $report += "`n- [$($violation.Severity)] $($violation.RuleId) in $($violation.FilePath):$($violation.LineNumber)"
        }
        if ($Comparison.TotalFixed -gt 20) {
            $report += "`n- ... and $($Comparison.TotalFixed - 20) more fixed issues"
        }
    }
    
    $report += "`n`n### ✗ New Issues: $($Comparison.TotalNew)`n"
    
    if ($Comparison.TotalNew -gt 0) {
        foreach ($violation in $Comparison.NewViolations | Select-Object -First 20) {
            $report += "`n- [$($violation.Severity)] $($violation.RuleId) in $($violation.FilePath):$($violation.LineNumber)"
            $report += "`n  - $($violation.Message)"
        }
        if ($Comparison.TotalNew -gt 20) {
            $report += "`n- ... and $($Comparison.TotalNew - 20) more new issues"
        }
    }
    
    return $report
}

function Remove-Baseline {
    <#
    .SYNOPSIS
        Removes a baseline file
    .PARAMETER Path
        Path to baseline file to remove
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    if (Test-Path $Path) {
        if ($PSCmdlet.ShouldProcess($Path, "Remove baseline")) {
            Remove-Item -Path $Path -Force
            Write-Host "Baseline removed: $Path" -ForegroundColor Green
        }
    } else {
        Write-Warning "Baseline file not found: $Path"
    }
}

function Copy-BaselineForTeam {
    <#
    .SYNOPSIS
        Prepares a baseline for team sharing by adding metadata
    .PARAMETER SourcePath
        Path to source baseline file
    .PARAMETER DestinationPath
        Path where team baseline will be saved
    .PARAMETER TeamName
        Name of the team
    .PARAMETER SharedBy
        Person sharing the baseline
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,
        
        [Parameter(Mandatory)]
        [string]$DestinationPath,
        
        [Parameter()]
        [string]$TeamName = "Default",
        
        [Parameter()]
        [string]$SharedBy
    )
    
    if (-not (Test-Path $SourcePath)) {
        throw "Source baseline not found: $SourcePath"
    }
    
    $baselineData = Get-Content $SourcePath -Raw | ConvertFrom-Json
    
    # Add team metadata
    $sharedBy = if ($SharedBy) { $SharedBy } else {
        if ($env:USER) { $env:USER } elseif ($env:USERNAME) { $env:USERNAME } else { "unknown" }
    }
    
    $teamBaseline = @{
        OriginalBaseline = $baselineData
        TeamMetadata = @{
            TeamName = $TeamName
            SharedBy = $sharedBy
            SharedAt = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssZ')
            SourceFile = $SourcePath
        }
    }
    
    $teamBaseline | ConvertTo-Json -Depth 20 | Out-File -FilePath $DestinationPath -Encoding UTF8
    
    Write-Host "Team baseline created: $DestinationPath" -ForegroundColor Green
    Write-Host "  Team: $TeamName" -ForegroundColor Gray
    Write-Host "  Shared by: $sharedBy" -ForegroundColor Gray
}

# Export module members
Export-ModuleMember -Function @(
    'New-BaselineVersion',
    'Get-BaselineHistory',
    'Compare-Baseline',
    'Export-BaselineReport',
    'Remove-Baseline',
    'Copy-BaselineForTeam'
)

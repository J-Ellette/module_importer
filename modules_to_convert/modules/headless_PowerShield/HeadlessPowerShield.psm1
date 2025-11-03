<#
.SYNOPSIS
    Headless PowerShield Module - Embeddable Security Analysis
    
.DESCRIPTION
    A lightweight, embeddable version of PowerShield for integration into other software.
    Provides core security analysis capabilities without GUI, GitHub Actions, or VS Code dependencies.
    
.NOTES
    Version: 2.0.0-headless
    Author: PowerShield Team
    
.EXAMPLE
    Import-Module .\HeadlessPowerShield.psm1
    $analyzer = Initialize-PowerShield
    $result = Invoke-Analysis -Path "C:\Scripts\MyScript.ps1"
#>

using namespace System.Management.Automation.Language

# Import core modules
$ModuleRoot = $PSScriptRoot
Import-Module "$ModuleRoot\src\PowerShellSecurityAnalyzer.psm1" -Force
Import-Module "$ModuleRoot\src\ConfigLoader.psm1" -Force -ErrorAction SilentlyContinue
Import-Module "$ModuleRoot\src\SuppressionParser.psm1" -Force -ErrorAction SilentlyContinue
Import-Module "$ModuleRoot\src\InputValidation.psm1" -Force -ErrorAction SilentlyContinue
Import-Module "$ModuleRoot\src\CustomRuleLoader.psm1" -Force -ErrorAction SilentlyContinue
Import-Module "$ModuleRoot\src\SecretScanner.psm1" -Force -ErrorAction SilentlyContinue
Import-Module "$ModuleRoot\src\BaselineManager.psm1" -Force -ErrorAction SilentlyContinue
Import-Module "$ModuleRoot\src\ComplianceReporter.psm1" -Force -ErrorAction SilentlyContinue

<#
.SYNOPSIS
    Initializes the PowerShield analyzer with optional configuration.
    
.DESCRIPTION
    Creates and configures a PowerShield security analyzer instance.
    Optionally loads custom rules and configuration.
    
.PARAMETER ConfigPath
    Path to a configuration file (JSON or PSD1).
    
.PARAMETER CustomRulesPath
    Path to a directory containing custom security rules.
    
.PARAMETER EnableSecretScanning
    Enables secret scanning capabilities.
    
.OUTPUTS
    Returns a configured analyzer instance.
    
.EXAMPLE
    $analyzer = Initialize-PowerShield
    
.EXAMPLE
    $analyzer = Initialize-PowerShield -ConfigPath ".\config.json" -EnableSecretScanning
#>
function Initialize-PowerShield {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath,
        
        [Parameter()]
        [string]$CustomRulesPath,
        
        [Parameter()]
        [switch]$EnableSecretScanning
    )
    
    try {
        # Create analyzer instance
        $analyzer = New-SecurityAnalyzer
        
        # Load configuration if provided
        if ($ConfigPath -and (Test-Path $ConfigPath)) {
            Write-Verbose "Loading configuration from: $ConfigPath"
            $config = Get-PowerShieldConfig -ConfigPath $ConfigPath
            
            # Apply configuration settings
            if ($config.MaxFileSize) {
                $analyzer.MaxFileSize = $config.MaxFileSize
            }
            if ($config.AnalysisTimeout) {
                $analyzer.AnalysisTimeout = $config.AnalysisTimeout
            }
        }
        
        # Load custom rules if provided
        if ($CustomRulesPath -and (Test-Path $CustomRulesPath)) {
            Write-Verbose "Loading custom rules from: $CustomRulesPath"
            $customRules = Import-CustomSecurityRules -RulesPath $CustomRulesPath
            foreach ($rule in $customRules) {
                $analyzer.SecurityRules.Add($rule)
            }
        }
        
        return $analyzer
    }
    catch {
        Write-Error "Failed to initialize PowerShield: $_"
        throw
    }
}

<#
.SYNOPSIS
    Analyzes a PowerShell script or workspace for security vulnerabilities.
    
.DESCRIPTION
    Performs comprehensive security analysis on PowerShell scripts, detecting vulnerabilities,
    insecure practices, and compliance issues.
    
.PARAMETER Path
    Path to a PowerShell script file or directory to analyze.
    
.PARAMETER Analyzer
    Pre-configured analyzer instance from Initialize-PowerShield.
    If not provided, a default analyzer will be created.
    
.PARAMETER Recursive
    When analyzing a directory, recursively scan all subdirectories.
    
.PARAMETER ExcludePath
    Array of paths to exclude from analysis.
    
.PARAMETER IncludeSuppressions
    Include suppressed violations in the results.
    
.PARAMETER SuppressionFile
    Path to a suppression file defining violations to ignore.
    
.OUTPUTS
    Returns an analysis result object with violations, summary, and metadata.
    
.EXAMPLE
    $result = Invoke-Analysis -Path ".\MyScript.ps1"
    
.EXAMPLE
    $analyzer = Initialize-PowerShield -EnableSecretScanning
    $result = Invoke-Analysis -Path ".\Scripts" -Analyzer $analyzer -Recursive
    
.EXAMPLE
    $result = Invoke-Analysis -Path ".\Scripts" -SuppressionFile ".\suppressions.json"
#>
function Invoke-Analysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Path,
        
        [Parameter()]
        [object]$Analyzer,
        
        [Parameter()]
        [switch]$Recursive,
        
        [Parameter()]
        [string[]]$ExcludePath,
        
        [Parameter()]
        [switch]$IncludeSuppressions,
        
        [Parameter()]
        [string]$SuppressionFile
    )
    
    try {
        # Create analyzer if not provided
        if (-not $Analyzer) {
            Write-Verbose "Creating default analyzer"
            $Analyzer = Initialize-PowerShield
        }
        
        # Validate path
        if (-not (Test-Path $Path)) {
            throw "Path not found: $Path"
        }
        
        $Path = Resolve-Path $Path
        
        # Load suppressions if provided
        $suppressions = @()
        if ($SuppressionFile -and (Test-Path $SuppressionFile)) {
            Write-Verbose "Loading suppressions from: $SuppressionFile"
            $suppressions = Import-SuppressionFile -Path $SuppressionFile
        }
        
        # Determine if single file or workspace
        $item = Get-Item $Path
        
        if ($item.PSIsContainer) {
            Write-Verbose "Analyzing workspace: $Path"
            $result = Invoke-WorkspaceAnalysis -WorkspacePath $Path
        }
        else {
            Write-Verbose "Analyzing file: $Path"
            $result = Invoke-SecurityAnalysis -ScriptPath $Path
        }
        
        # Apply suppressions if not including them
        if ($suppressions.Count -gt 0 -and -not $IncludeSuppressions) {
            Write-Verbose "Applying suppressions: $($suppressions.Count) rules"
            $result = Remove-SuppressedViolations -Result $result -Suppressions $suppressions
        }
        
        # Add metadata
        $result | Add-Member -MemberType NoteProperty -Name 'Timestamp' -Value (Get-Date -Format 'o') -Force
        $result | Add-Member -MemberType NoteProperty -Name 'PowerShieldVersion' -Value '2.0.0-headless' -Force
        $result | Add-Member -MemberType NoteProperty -Name 'AnalyzedPath' -Value $Path -Force
        
        return $result
    }
    catch {
        Write-Error "Analysis failed: $_"
        throw
    }
}

<#
.SYNOPSIS
    Retrieves the list of active security rules.
    
.DESCRIPTION
    Returns information about all security rules available in the analyzer,
    including default rules and any custom rules that have been loaded.
    
.PARAMETER Analyzer
    Pre-configured analyzer instance from Initialize-PowerShield.
    If not provided, a default analyzer will be created.
    
.PARAMETER RuleId
    Optional filter to retrieve a specific rule by ID.
    
.PARAMETER Severity
    Optional filter to retrieve rules by severity level.
    
.OUTPUTS
    Returns an array of security rule objects.
    
.EXAMPLE
    $rules = Get-SecurityRules
    
.EXAMPLE
    $analyzer = Initialize-PowerShield
    $highRules = Get-SecurityRules -Analyzer $analyzer -Severity High
    
.EXAMPLE
    $rule = Get-SecurityRules -RuleId "InsecureHashAlgorithms"
#>
function Get-SecurityRules {
    [CmdletBinding()]
    param(
        [Parameter()]
        [object]$Analyzer,
        
        [Parameter()]
        [string]$RuleId,
        
        [Parameter()]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity
    )
    
    try {
        # Create analyzer if not provided
        if (-not $Analyzer) {
            $Analyzer = Initialize-PowerShield
        }
        
        $rules = $Analyzer.SecurityRules
        
        # Filter by RuleId if specified
        if ($RuleId) {
            $rules = $rules | Where-Object { $_.Id -eq $RuleId }
        }
        
        # Filter by Severity if specified
        if ($Severity) {
            $rules = $rules | Where-Object { $_.Severity.ToString() -eq $Severity }
        }
        
        # Return rule information
        return $rules | ForEach-Object {
            [PSCustomObject]@{
                Id = $_.Id
                Description = $_.Description
                Severity = $_.Severity.ToString()
                Category = if ($_.PSObject.Properties['Category']) { $_.Category } else { 'General' }
            }
        }
    }
    catch {
        Write-Error "Failed to retrieve security rules: $_"
        throw
    }
}

<#
.SYNOPSIS
    Sets configuration options for the PowerShield analyzer.
    
.DESCRIPTION
    Updates configuration settings for an existing analyzer instance,
    such as file size limits, timeout values, and analysis options.
    
.PARAMETER Analyzer
    The analyzer instance to configure.
    
.PARAMETER MaxFileSize
    Maximum file size in bytes to analyze (default: 10MB).
    
.PARAMETER AnalysisTimeout
    Maximum time in seconds to spend analyzing a single file (default: 30).
    
.PARAMETER Verbose
    Enable verbose output during analysis.
    
.EXAMPLE
    $analyzer = Initialize-PowerShield
    Set-Configuration -Analyzer $analyzer -MaxFileSize 20MB -AnalysisTimeout 60
#>
function Set-Configuration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Analyzer,
        
        [Parameter()]
        [int64]$MaxFileSize,
        
        [Parameter()]
        [int]$AnalysisTimeout
    )
    
    try {
        if ($MaxFileSize) {
            Write-Verbose "Setting MaxFileSize to: $MaxFileSize bytes"
            $Analyzer.MaxFileSize = $MaxFileSize
        }
        
        if ($AnalysisTimeout) {
            Write-Verbose "Setting AnalysisTimeout to: $AnalysisTimeout seconds"
            $Analyzer.AnalysisTimeout = $AnalysisTimeout
        }
    }
    catch {
        Write-Error "Failed to set configuration: $_"
        throw
    }
}

<#
.SYNOPSIS
    Exports analysis results in various formats.
    
.DESCRIPTION
    Converts PowerShield analysis results to different output formats
    suitable for integration with other tools and systems.
    
.PARAMETER Result
    The analysis result object to export.
    
.PARAMETER Format
    Output format: JSON, SARIF, CSV, or PSObject (default: PSObject).
    
.PARAMETER OutputPath
    Optional path to write the output file.
    
.OUTPUTS
    Returns the formatted results or writes to file if OutputPath is specified.
    
.EXAMPLE
    $result = Invoke-Analysis -Path ".\MyScript.ps1"
    Export-AnalysisResult -Result $result -Format JSON
    
.EXAMPLE
    Export-AnalysisResult -Result $result -Format SARIF -OutputPath ".\results.sarif"
#>
function Export-AnalysisResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Result,
        
        [Parameter()]
        [ValidateSet('PSObject', 'JSON', 'SARIF', 'CSV')]
        [string]$Format = 'PSObject',
        
        [Parameter()]
        [string]$OutputPath
    )
    
    process {
        try {
            $output = switch ($Format) {
                'PSObject' {
                    $Result
                }
                'JSON' {
                    $Result | ConvertTo-Json -Depth 10
                }
                'SARIF' {
                    # Basic SARIF conversion (can be enhanced)
                    Convert-ToSARIF -Result $Result
                }
                'CSV' {
                    # Flatten violations for CSV
                    $Result.Results | ForEach-Object {
                        $file = $_.FilePath
                        $_.Violations | ForEach-Object {
                            [PSCustomObject]@{
                                File = $file
                                RuleId = $_.RuleId
                                Severity = $_.Severity
                                Message = $_.Message
                                Line = $_.LineNumber
                                Column = $_.ColumnNumber
                            }
                        }
                    } | ConvertTo-Csv -NoTypeInformation
                }
            }
            
            if ($OutputPath) {
                $output | Out-File -FilePath $OutputPath -Encoding utf8
                Write-Verbose "Results exported to: $OutputPath"
            }
            else {
                return $output
            }
        }
        catch {
            Write-Error "Failed to export results: $_"
            throw
        }
    }
}

# Helper function for SARIF conversion (basic implementation)
function Convert-ToSARIF {
    param([object]$Result)
    
    $sarif = @{
        version = '2.1.0'
        '$schema' = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json'
        runs = @(
            @{
                tool = @{
                    driver = @{
                        name = 'PowerShield'
                        version = '2.0.0-headless'
                        informationUri = 'https://github.com/J-Ellette/PowerShield'
                    }
                }
                results = @()
            }
        )
    }
    
    foreach ($fileResult in $Result.Results) {
        foreach ($violation in $fileResult.Violations) {
            $sarif.runs[0].results += @{
                ruleId = $violation.RuleId
                level = switch ($violation.Severity) {
                    'Critical' { 'error' }
                    'High' { 'error' }
                    'Medium' { 'warning' }
                    'Low' { 'note' }
                    default { 'warning' }
                }
                message = @{
                    text = $violation.Message
                }
                locations = @(
                    @{
                        physicalLocation = @{
                            artifactLocation = @{
                                uri = $fileResult.FilePath
                            }
                            region = @{
                                startLine = $violation.LineNumber
                                startColumn = $violation.ColumnNumber
                            }
                        }
                    }
                )
            }
        }
    }
    
    return ($sarif | ConvertTo-Json -Depth 10)
}

# Helper function for filtering suppressions
function Remove-SuppressedViolations {
    param(
        [object]$Result,
        [array]$Suppressions
    )
    
    foreach ($fileResult in $Result.Results) {
        $fileResult.Violations = $fileResult.Violations | Where-Object {
            $violation = $_
            $isSuppressed = $false
            
            foreach ($suppression in $Suppressions) {
                if ($suppression.RuleId -eq $violation.RuleId) {
                    if ($suppression.FilePath -and $fileResult.FilePath -like "*$($suppression.FilePath)") {
                        $isSuppressed = $true
                        break
                    }
                    elseif (-not $suppression.FilePath) {
                        $isSuppressed = $true
                        break
                    }
                }
            }
            
            -not $isSuppressed
        }
    }
    
    return $Result
}

# Export public functions
Export-ModuleMember -Function @(
    'Initialize-PowerShield',
    'Invoke-Analysis',
    'Get-SecurityRules',
    'Set-Configuration',
    'Export-AnalysisResult'
)

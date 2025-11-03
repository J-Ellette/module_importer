# PowerShield Headless Module - Quick Start Guide

Get started with the PowerShield Headless Module in 5 minutes!

## 📋 Prerequisites

- PowerShell 7.0 or later
- Windows, Linux, or macOS

Check your PowerShell version:
```powershell
$PSVersionTable.PSVersion
```

## 🚀 Installation

### Option 1: Local Import (Recommended)

```powershell
# Navigate to the headless module directory
cd C:\GitHub\PowerShield\headless_PowerShield

# Import the module
Import-Module .\HeadlessPowerShield.psm1
```

### Option 2: Add to PowerShell Profile

Add this to your PowerShell profile (`$PROFILE`):
```powershell
Import-Module "C:\GitHub\PowerShield\headless_PowerShield\HeadlessPowerShield.psm1"
```

### Option 3: Copy to Modules Directory

```powershell
# Copy the entire headless_PowerShield directory to your modules path
$modulePath = "$HOME\Documents\PowerShell\Modules\HeadlessPowerShield"
Copy-Item -Path "C:\GitHub\PowerShield\headless_PowerShield" -Destination $modulePath -Recurse

# Import from modules path
Import-Module HeadlessPowerShield
```

## 🎯 Basic Usage

### 1. Analyze a Single Script

```powershell
# Import the module
Import-Module .\HeadlessPowerShield.psm1

# Analyze a script
$result = Invoke-Analysis -Path ".\MyScript.ps1"

# View violations
$result.Violations | Format-Table RuleId, Severity, Message, LineNumber
```

### 2. Analyze a Directory

```powershell
# Analyze all scripts in a directory
$result = Invoke-Analysis -Path ".\Scripts"

# View summary
$result.Summary

# View all violations
$result.Results | ForEach-Object {
    Write-Host "`nFile: $($_.FilePath)"
    $_.Violations | Format-Table RuleId, Severity, Message, LineNumber
}
```

### 3. Get Available Rules

```powershell
# List all security rules
Get-SecurityRules | Format-Table Id, Severity, Description

# Filter by severity
Get-SecurityRules -Severity Critical
Get-SecurityRules -Severity High
```

### 4. Export Results

```powershell
# Export to JSON
$result | Export-AnalysisResult -Format JSON -OutputPath "results.json"

# Export to SARIF (for GitHub Security tab)
$result | Export-AnalysisResult -Format SARIF -OutputPath "results.sarif"

# Export to CSV
$result | Export-AnalysisResult -Format CSV -OutputPath "results.csv"
```

## 🔧 Common Scenarios

### Scenario 1: Pre-Commit Hook

```powershell
# pre-commit.ps1
Import-Module .\PowerShield\HeadlessPowerShield.psm1

$result = Invoke-Analysis -Path ".\src" -Recursive

$criticalCount = ($result.Results.Violations | Where-Object { $_.Severity -eq 'Critical' }).Count

if ($criticalCount -gt 0) {
    Write-Error "Commit blocked: $criticalCount critical security violations found"
    exit 1
}

Write-Host "Security check passed!" -ForegroundColor Green
```

### Scenario 2: Build Validation

```powershell
# validate-build.ps1
Import-Module .\PowerShield\HeadlessPowerShield.psm1

$analyzer = Initialize-PowerShield
$result = Invoke-Analysis -Path ".\src" -Analyzer $analyzer -Recursive

# Fail build if high or critical violations found
$highOrCritical = $result.Results.Violations | Where-Object { 
    $_.Severity -eq 'High' -or $_.Severity -eq 'Critical' 
}

if ($highOrCritical.Count -gt 0) {
    Write-Error "Build failed: $($highOrCritical.Count) high/critical violations"
    
    # Export detailed report
    $result | Export-AnalysisResult -Format SARIF -OutputPath "build-security-report.sarif"
    
    exit 1
}
```

### Scenario 3: Scheduled Security Scan

```powershell
# daily-scan.ps1
Import-Module .\PowerShield\HeadlessPowerShield.psm1

$analyzer = Initialize-PowerShield -EnableSecretScanning
$result = Invoke-Analysis -Path "C:\Production\Scripts" -Analyzer $analyzer -Recursive

# Generate timestamped report
$timestamp = Get-Date -Format "yyyy-MM-dd-HHmmss"
$reportPath = ".\reports\security-scan-$timestamp.json"
$result | Export-AnalysisResult -Format JSON -OutputPath $reportPath

# Send alert if violations found
if ($result.Summary.TotalViolations -gt 0) {
    $subject = "Security Scan Alert: $($result.Summary.TotalViolations) violations found"
    $body = @"
Security scan completed at $(Get-Date)

Summary:
- Total Files: $($result.Summary.TotalFiles)
- Files with Issues: $($result.Summary.FilesWithViolations)
- Critical: $($result.Summary.ViolationsBySeverity.Critical)
- High: $($result.Summary.ViolationsBySeverity.High)
- Medium: $($result.Summary.ViolationsBySeverity.Medium)
- Low: $($result.Summary.ViolationsBySeverity.Low)

Report: $reportPath
"@
    
    Send-MailMessage -To "security@company.com" -Subject $subject -Body $body
}
```

### Scenario 4: Embed in Your Tool

```powershell
# MySecurityTool.psm1
$ModuleRoot = $PSScriptRoot
Import-Module "$ModuleRoot\lib\HeadlessPowerShield.psm1" -Prefix "PS"

function Invoke-MyCustomScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        
        [switch]$IncludeSecrets,
        
        [string]$OutputFormat = 'JSON'
    )
    
    # Initialize analyzer with your custom settings
    $analyzer = Initialize-PSPowerShield
    
    if ($IncludeSecrets) {
        # Add custom secret patterns
        # Your custom logic here
    }
    
    # Run analysis
    $result = Invoke-PSAnalysis -Path $Path -Analyzer $analyzer
    
    # Process results your way
    $customResult = @{
        Timestamp = Get-Date
        Path = $Path
        Tool = 'MySecurityTool'
        PowerShieldVersion = '2.0.0-headless'
        Findings = $result.Results.Violations | ForEach-Object {
            @{
                Type = 'Security'
                Severity = $_.Severity
                Rule = $_.RuleId
                Message = $_.Message
                Location = "$($_.LineNumber):$($_.ColumnNumber)"
            }
        }
    }
    
    # Export in your format
    switch ($OutputFormat) {
        'JSON' { $customResult | ConvertTo-Json -Depth 10 }
        'XML' { $customResult | ConvertTo-Xml -As String }
        default { $customResult }
    }
}

Export-ModuleMember -Function Invoke-MyCustomScan
```

## 📊 Understanding Results

### Result Structure

```powershell
@{
    FilePath = "C:\Scripts\MyScript.ps1"       # File that was analyzed
    Violations = @(...)                         # Array of violations found
    ParseErrors = @(...)                        # PowerShell parse errors
    RulesExecuted = 55                          # Number of rules executed
    Timestamp = "2025-01-23T10:30:00Z"         # Analysis timestamp
    PowerShieldVersion = "2.0.0-headless"      # Module version
    AnalyzedPath = "C:\Scripts\MyScript.ps1"   # Original path provided
}
```

### Violation Object

```powershell
@{
    RuleId = "InsecureHashAlgorithms"          # Rule identifier
    Severity = "High"                           # Critical, High, Medium, Low, Info
    Message = "MD5 hash detected..."            # Description of violation
    LineNumber = 42                             # Line number in file
    ColumnNumber = 5                            # Column number in file
    Extent = "Get-FileHash -Algorithm MD5"     # Code snippet
}
```

### Summary Object (Workspace Analysis)

```powershell
@{
    TotalFiles = 10                            # Files analyzed
    FilesWithViolations = 3                    # Files with issues
    TotalViolations = 15                       # Total violations found
    ViolationsBySeverity = @{
        Critical = 2
        High = 5
        Medium = 6
        Low = 2
        Info = 0
    }
}
```

## ⚙️ Configuration

### Create a Configuration File

```json
{
  "MaxFileSize": 10485760,
  "AnalysisTimeout": 30,
  "EnabledRules": ["*"],
  "DisabledRules": ["WriteHostDetection"],
  "CustomRulePaths": ["./rules/custom"],
  "SuppressionFile": "./suppressions.json"
}
```

### Use Configuration

```powershell
$analyzer = Initialize-PowerShield -ConfigPath ".\config.json"
$result = Invoke-Analysis -Path ".\Scripts" -Analyzer $analyzer
```

### Runtime Configuration

```powershell
$analyzer = Initialize-PowerShield
Set-Configuration -Analyzer $analyzer -MaxFileSize 20MB -AnalysisTimeout 60
```

## 🔇 Suppressing Violations

Create `suppressions.json`:

```json
{
  "suppressions": [
    {
      "RuleId": "InsecureHashAlgorithms",
      "FilePath": "legacy/old-script.ps1",
      "Justification": "Legacy code, planned for refactor Q2"
    },
    {
      "RuleId": "CredentialExposure",
      "FilePath": "tests/test-*.ps1",
      "Justification": "Test files with sample credentials"
    }
  ]
}
```

Use suppressions:

```powershell
$result = Invoke-Analysis -Path ".\Scripts" -SuppressionFile ".\suppressions.json"
```

## 🐛 Troubleshooting

### Module Won't Load

```powershell
# Check PowerShell version (needs 7.0+)
$PSVersionTable.PSVersion

# Try importing with verbose output
Import-Module .\HeadlessPowerShield.psm1 -Force -Verbose
```

### No Violations Detected

```powershell
# Verify rules are loaded
$analyzer = Initialize-PowerShield
Get-SecurityRules -Analyzer $analyzer

# Check file extension
# Module analyzes .ps1, .psm1, .psd1 files only
```

### Custom Rules Failing

Check the warnings in the output. Rules with `$using:` variables won't work in headless mode.

## 📚 Next Steps

1. **Read the full README**: `README.md` for complete API reference
2. **Run examples**: `.\Example-Usage.ps1` for hands-on demonstrations
3. **Add custom rules**: See custom rule documentation
4. **Integrate**: Embed into your tools and workflows

## 🔗 Resources

- [Main PowerShield Repository](https://github.com/J-Ellette/PowerShield)
- [Full Documentation](../docs/)
- [Security Rules Reference](../rules/)
- [Configuration Guide](../docs/CONFIGURATION_GUIDE.md)

## 💡 Tips

1. **Start small**: Analyze one script first, then expand to directories
2. **Review rules**: Use `Get-SecurityRules` to understand what's checked
3. **Use suppressions**: Don't let false positives slow you down
4. **Automate**: Integrate into your build/deployment pipeline
5. **Export results**: Keep records for audit and compliance

---

**Ready to secure your PowerShell code?** Start with `Invoke-Analysis` and go from there! 🛡️

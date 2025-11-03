# PowerShield Headless Module

A lightweight, embeddable version of PowerShield for integration into other software. Provides core security analysis capabilities without GUI, GitHub Actions, or VS Code dependencies.

## 🎯 Purpose

The headless module is designed for:
- **Embedding in other tools**: Use PowerShield's analysis engine within your own software
- **Automation scenarios**: Run security analysis in scripts and pipelines without dependencies
- **Minimal footprint**: Only core analysis modules, no UI or CI/CD integrations
- **Programmatic access**: Simple, clean API for developers

## 📦 What's Included

### Core Modules
- `PowerShellSecurityAnalyzer.psm1` - Main analysis engine with 52+ security rules
- `ConfigLoader.psm1` - Configuration management
- `SuppressionParser.psm1` - Violation suppression handling
- `InputValidation.psm1` - Input validation and sanitization
- `CustomRuleLoader.psm1` - Custom rule loading
- `SecretScanner.psm1` - Secret and credential detection
- `BaselineManager.psm1` - Baseline management for tracking changes
- `ComplianceReporter.psm1` - Compliance reporting and frameworks

### Entry Point
- `HeadlessPowerShield.psm1` - Simplified API for embedding

## 🚀 Quick Start

### Basic Usage

```powershell
# Import the headless module
Import-Module .\HeadlessPowerShield.psm1

# Analyze a single file
$result = Invoke-Analysis -Path "C:\Scripts\MyScript.ps1"

# Display violations
$result.Results.Violations | Format-Table RuleId, Severity, Message, LineNumber
```

### Advanced Usage

```powershell
# Initialize with custom configuration
$analyzer = Initialize-PowerShield -ConfigPath ".\config.json" -EnableSecretScanning

# Analyze a workspace
$result = Invoke-Analysis -Path "C:\Scripts" -Analyzer $analyzer -Recursive

# Export to different formats
$result | Export-AnalysisResult -Format JSON -OutputPath "results.json"
$result | Export-AnalysisResult -Format SARIF -OutputPath "results.sarif"
```

## 📖 API Reference

### Initialize-PowerShield

Creates and configures a PowerShield analyzer instance.

```powershell
$analyzer = Initialize-PowerShield [-ConfigPath <string>] [-CustomRulesPath <string>] [-EnableSecretScanning]
```

**Parameters:**
- `ConfigPath` - Path to configuration file (JSON or PSD1)
- `CustomRulesPath` - Path to directory containing custom rules
- `EnableSecretScanning` - Enable secret detection

### Invoke-Analysis

Analyzes a PowerShell script or workspace for security vulnerabilities.

```powershell
$result = Invoke-Analysis -Path <string> 
    [-Analyzer <object>] 
    [-Recursive] 
    [-ExcludePath <string[]>] 
    [-IncludeSuppressions] 
    [-SuppressionFile <string>]
```

**Parameters:**
- `Path` (required) - Path to script file or directory
- `Analyzer` - Pre-configured analyzer instance
- `Recursive` - Recursively scan subdirectories
- `ExcludePath` - Paths to exclude from analysis
- `IncludeSuppressions` - Include suppressed violations in results
- `SuppressionFile` - Path to suppression file

**Returns:** Analysis result object with violations, summary, and metadata

### Get-SecurityRules

Retrieves the list of active security rules.

```powershell
$rules = Get-SecurityRules [-Analyzer <object>] [-RuleId <string>] [-Severity <string>]
```

**Parameters:**
- `Analyzer` - Pre-configured analyzer instance
- `RuleId` - Filter by specific rule ID
- `Severity` - Filter by severity (Critical, High, Medium, Low, Info)

**Returns:** Array of security rule objects

### Set-Configuration

Updates configuration settings for an analyzer instance.

```powershell
Set-Configuration -Analyzer <object> [-MaxFileSize <int64>] [-AnalysisTimeout <int>]
```

**Parameters:**
- `Analyzer` (required) - The analyzer instance to configure
- `MaxFileSize` - Maximum file size in bytes (default: 10MB)
- `AnalysisTimeout` - Maximum analysis time per file in seconds (default: 30)

### Export-AnalysisResult

Exports analysis results in various formats.

```powershell
$result | Export-AnalysisResult [-Format <string>] [-OutputPath <string>]
```

**Parameters:**
- `Format` - Output format: PSObject, JSON, SARIF, or CSV (default: PSObject)
- `OutputPath` - Optional path to write output file

## 🔧 Configuration

### Configuration File Format

Create a JSON or PSD1 configuration file:

```json
{
  "MaxFileSize": 10485760,
  "AnalysisTimeout": 30,
  "EnabledRules": ["*"],
  "DisabledRules": [],
  "CustomRulePaths": ["./rules/custom"],
  "SuppressionFile": "./suppressions.json"
}
```

### Suppression File Format

Define violations to suppress:

```json
{
  "suppressions": [
    {
      "RuleId": "InsecureHashAlgorithms",
      "FilePath": "legacy/old-script.ps1",
      "Justification": "Legacy code, planned for refactor"
    }
  ]
}
```

## 📊 Result Object Structure

```powershell
@{
    Results = @(
        @{
            FilePath = "C:\Scripts\MyScript.ps1"
            Violations = @(
                @{
                    RuleId = "InsecureHashAlgorithms"
                    Severity = "High"
                    Message = "MD5 hash algorithm detected"
                    LineNumber = 42
                    ColumnNumber = 5
                    Extent = "Get-FileHash -Algorithm MD5"
                }
            )
        }
    )
    Summary = @{
        TotalFiles = 1
        FilesWithViolations = 1
        TotalViolations = 1
        ViolationsBySeverity = @{
            Critical = 0
            High = 1
            Medium = 0
            Low = 0
            Info = 0
        }
    }
    Timestamp = "2025-01-23T10:30:00Z"
    PowerShieldVersion = "2.0.0-headless"
    AnalyzedPath = "C:\Scripts\MyScript.ps1"
}
```

## 🔌 Integration Examples

### Embed in Your Module

```powershell
# MySecurityTool.psm1
$ModuleRoot = $PSScriptRoot
Import-Module "$ModuleRoot\PowerShield\HeadlessPowerShield.psm1" -Prefix "PS"

function Invoke-MySecurityScan {
    param([string]$Path)
    
    $analyzer = Initialize-PSPowerShield
    $result = Invoke-PSAnalysis -Path $Path -Analyzer $analyzer
    
    # Process results in your way
    foreach ($violation in $result.Results.Violations) {
        Write-MyCustomLog -Violation $violation
    }
}
```

### Use in Build Script

```powershell
# build.ps1
Import-Module .\PowerShield\HeadlessPowerShield.psm1

Write-Host "Running security analysis..."
$result = Invoke-Analysis -Path ".\src" -Recursive

$criticalCount = ($result.Results.Violations | Where-Object { $_.Severity -eq 'Critical' }).Count

if ($criticalCount -gt 0) {
    Write-Error "Build failed: $criticalCount critical security violations found"
    exit 1
}
```

### Automated Reporting

```powershell
# daily-scan.ps1
Import-Module .\PowerShield\HeadlessPowerShield.psm1

$analyzer = Initialize-PowerShield -EnableSecretScanning
$result = Invoke-Analysis -Path "C:\Production\Scripts" -Analyzer $analyzer -Recursive

# Export to multiple formats
$result | Export-AnalysisResult -Format JSON -OutputPath "reports\scan-$(Get-Date -F yyyy-MM-dd).json"
$result | Export-AnalysisResult -Format SARIF -OutputPath "reports\scan-$(Get-Date -F yyyy-MM-dd).sarif"

# Send email if violations found
if ($result.Summary.TotalViolations -gt 0) {
    Send-MailMessage -To "security@company.com" -Subject "Daily Security Scan Results" -Body "..."
}
```

## 🛡️ Security Rules

The headless module includes 52+ security rules covering:

- **Cryptography**: Insecure hash algorithms (MD5, SHA1), weak encryption
- **Credentials**: Plaintext passwords, exposed secrets, API keys
- **Code Injection**: `Invoke-Expression`, `Invoke-Command` with user input
- **Certificate Validation**: SSL/TLS bypass, certificate validation disabled
- **Command Execution**: Unsafe command execution patterns
- **Network Security**: Insecure protocols, unvalidated URLs
- **File Operations**: Path traversal, insecure file permissions
- **Registry Access**: Unsafe registry modifications
- **Data Handling**: SQL injection, XSS, insecure deserialization

## 📝 Requirements

- **PowerShell 7.0+** (required for class-based modules)
- **Windows, Linux, or macOS**
- **No external dependencies**

## 🔄 Differences from Full PowerShield

| Feature | Full PowerShield | Headless Module |
|---------|-----------------|-----------------|
| Core Analysis Engine | ✅ | ✅ |
| 52+ Security Rules | ✅ | ✅ |
| Custom Rules | ✅ | ✅ |
| Secret Scanning | ✅ | ✅ |
| Baseline Management | ✅ | ✅ |
| Compliance Reporting | ✅ | ✅ |
| VS Code Extension | ✅ | ❌ |
| GitHub Actions Workflow | ✅ | ❌ |
| Auto-Fix Action | ✅ | ❌ |
| PR Comments | ✅ | ❌ |
| CI/CD Adapters | ✅ | ❌ |
| Webhook Notifications | ✅ | ❌ |
| Performance Profiling | ✅ | ❌ |
| Pester Integration | ✅ | ❌ |
| Artifact Management | ✅ | ❌ |

## 📄 License

Same as PowerShield - see LICENSE file in repository root.

## 🤝 Support

For issues, questions, or contributions, please refer to the main PowerShield repository:
https://github.com/J-Ellette/PowerShield

## 🔗 Related

- [Main PowerShield Repository](https://github.com/J-Ellette/PowerShield)
- [PowerShield Documentation](../docs/)
- [Security Rules Reference](../rules/)
- [CI/CD Integration Guide](../docs/CI_CD_INTEGRATION.md)

---

**PowerShield Headless Module v2.0.0** - Comprehensive PowerShell Security Analysis

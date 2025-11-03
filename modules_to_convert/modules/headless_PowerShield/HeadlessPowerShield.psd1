#
# Module manifest for module 'HeadlessPowerShield'
#

@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'HeadlessPowerShield.psm1'

    # Version number of this module.
    ModuleVersion = '2.0.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Core', 'Desktop')

    # ID used to uniquely identify this module
    GUID = 'a1b2c3d4-e5f6-4789-90ab-cdef12345678'

    # Author of this module
    Author = 'PowerShield Team'

    # Company or vendor of this module
    CompanyName = 'PowerShield'

    # Copyright statement for this module
    Copyright = '(c) 2025 PowerShield Team. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Headless PowerShield Module - Lightweight, embeddable PowerShell security analysis for integration into other software. Provides core security analysis capabilities without GUI, GitHub Actions, or VS Code dependencies.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '7.0'

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        'Initialize-PowerShield',
        'Invoke-Analysis',
        'Get-SecurityRules',
        'Set-Configuration',
        'Export-AnalysisResult'
    )

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @(
                'Security',
                'PowerShell',
                'Analysis',
                'Static-Analysis',
                'SAST',
                'Vulnerability-Scanning',
                'Code-Quality',
                'Headless',
                'Embeddable',
                'API',
                'DevSecOps',
                'Security-Scanning',
                'Compliance',
                'Best-Practices',
                'Windows',
                'Linux',
                'macOS'
            )

            # A URL to the license for this module.
            LicenseUri = 'https://github.com/J-Ellette/PowerShield/blob/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/J-Ellette/PowerShield'

            # ReleaseNotes of this module
            ReleaseNotes = @'
# PowerShield Headless Module v2.0.0

## What's New
- Lightweight, embeddable version of PowerShield
- Clean API designed for integration into other software
- Core security analysis with 52+ rules
- No dependencies on GUI, GitHub Actions, or VS Code
- Support for custom rules and configuration
- Multiple export formats (JSON, SARIF, CSV)
- Secret scanning capabilities
- Baseline management
- Compliance reporting

## Included Components
- PowerShellSecurityAnalyzer: Core analysis engine
- ConfigLoader: Configuration management
- SuppressionParser: Violation suppression
- InputValidation: Input validation
- CustomRuleLoader: Custom rule loading
- SecretScanner: Secret detection
- BaselineManager: Baseline tracking
- ComplianceReporter: Compliance frameworks

## Requirements
- PowerShell 7.0+
- Windows, Linux, or macOS
- No external dependencies

## Usage
```powershell
Import-Module HeadlessPowerShield
$result = Invoke-Analysis -Path ".\MyScript.ps1"
```

For more information, see README.md
'@
        }
    }

    # HelpInfo URI of this module
    HelpInfoURI = 'https://github.com/J-Ellette/PowerShield/blob/main/headless_PowerShield/README.md'
}

#Requires -Version 7.0

<#
.SYNOPSIS
    Configuration loader for PowerShield
.DESCRIPTION
    Loads and validates PowerShield configuration from .powershield.yml files with hierarchical support.
.NOTES
    Version: 1.0.0
    Author: PowerShield Project
#>

# Check if powershell-yaml module is available
$yamlAvailable = $null -ne (Get-Module -ListAvailable -Name 'powershell-yaml')

class PowerShieldConfiguration {
    [string]$Version
    [hashtable]$Analysis
    [hashtable]$Rules
    [hashtable]$AutoFix
    [hashtable]$Suppressions
    [hashtable]$Reporting
    [hashtable]$CI
    [array]$Webhooks
    [hashtable]$Enterprise
    [hashtable]$Hooks
    [hashtable]$Performance
    [hashtable]$Integrations
    [hashtable]$CustomRules

    PowerShieldConfiguration() {
        $this.Version = '1.0'
        $this.Analysis = @{
            severity_threshold = 'Medium'
            max_file_size = 10485760
            timeout_seconds = 30
            parallel_analysis = $true
            worker_threads = 0  # 0 = auto-detect based on CPU cores
            exclude_paths = @('**/node_modules/**', '**/dist/**', '**/*.min.ps1', '.github/**')
            exclude_files = @('*.tests.ps1')
        }
        $this.Rules = @{
            InsecureHashAlgorithms = @{ enabled = $true; severity = 'High' }
            CredentialExposure = @{ enabled = $true; severity = 'Critical'; check_comments = $true; min_password_length = 8 }
            CommandInjection = @{ enabled = $true; severity = 'Critical' }
            CertificateValidation = @{ enabled = $true; severity = 'High' }
        }
        $this.AutoFix = @{
            enabled = $true
            provider = 'github-models'
            model = 'gpt-4o-mini'
            max_fixes = 10
            confidence_threshold = 0.8
            apply_automatically = $false
            fallback_to_templates = $true
            rule_fixes = @{
                InsecureHashAlgorithms = $true
                CredentialExposure = $true
                CommandInjection = $false
                CertificateValidation = $false
            }
        }
        $this.Suppressions = @{
            require_justification = $true
            max_duration_days = 90
            allow_permanent = $false
        }
        $this.Reporting = @{
            formats = @('sarif', 'json', 'markdown')
            output_dir = '.powershield-reports'
            sarif = @{
                include_code_flows = $true
                include_fixes = $true
            }
            markdown = @{
                include_severity_summary = $true
                include_top_issues = 5
            }
        }
        $this.CI = @{
            fail_on = @('Critical', 'High')
            max_warnings = 50
            baseline_mode = $false
            baseline_file = '.powershield-baseline.sarif'
            incremental_mode = $false  # Only analyze changed files in CI/CD
        }
        $this.Hooks = @{
            enabled = $true
            block_on = @('Critical', 'High')
            auto_fix = $false
            skip_on_no_violations = $true
        }
        $this.Performance = @{
            enable_cache = $true
            cache_dir = '.powershield-cache'
            cache_max_age = 86400  # 24 hours in seconds
            track_metrics = $true
        }
        $this.Integrations = @{
            pester = @{
                enabled = $false
                security_tests = './tests/Security.Tests.ps1'
                run_after_fixes = $true
                validate_fixes = $true
            }
        }
        $this.CustomRules = @{
            enabled = $true
            directories = @('./rules/custom', './rules/community')
            auto_load = $true
        }
    }

    [void] Merge([hashtable]$other) {
        if ($other.ContainsKey('version')) { $this.Version = $other.version }
        if ($other.ContainsKey('analysis')) { $this.Analysis = $this.MergeHashtables($this.Analysis, $other.analysis) }
        if ($other.ContainsKey('autofix')) { $this.AutoFix = $this.MergeHashtables($this.AutoFix, $other.autofix) }
        if ($other.ContainsKey('suppressions')) { $this.Suppressions = $this.MergeHashtables($this.Suppressions, $other.suppressions) }
        if ($other.ContainsKey('reporting')) { $this.Reporting = $this.MergeHashtables($this.Reporting, $other.reporting) }
        if ($other.ContainsKey('ci')) { $this.CI = $this.MergeHashtables($this.CI, $other.ci) }
        if ($other.ContainsKey('webhooks')) { $this.Webhooks = $other.webhooks }
        if ($other.ContainsKey('enterprise')) { $this.Enterprise = $other.enterprise }
        if ($other.ContainsKey('hooks')) { $this.Hooks = $this.MergeHashtables($this.Hooks, $other.hooks) }
        if ($other.ContainsKey('performance')) { $this.Performance = $this.MergeHashtables($this.Performance, $other.performance) }
        if ($other.ContainsKey('integrations')) { $this.Integrations = $this.MergeHashtables($this.Integrations, $other.integrations) }
        if ($other.ContainsKey('custom_rules')) { $this.CustomRules = $this.MergeHashtables($this.CustomRules, $other.custom_rules) }
        
        # Merge rules specially to preserve per-rule config
        if ($other.ContainsKey('rules')) {
            foreach ($ruleId in $other.rules.Keys) {
                if ($this.Rules.ContainsKey($ruleId)) {
                    $this.Rules[$ruleId] = $this.MergeHashtables($this.Rules[$ruleId], $other.rules[$ruleId])
                } else {
                    $this.Rules[$ruleId] = $other.rules[$ruleId]
                }
            }
        }
    }

    [hashtable] MergeHashtables([hashtable]$target, $source) {
        if ($null -eq $source) {
            return $target.Clone()
        }
        
        if ($source -is [string] -and [string]::IsNullOrEmpty($source)) {
            return $target.Clone()
        }
        
        if ($source -isnot [hashtable]) {
            Write-Warning "MergeHashtables: source parameter is not a hashtable, type: $($source.GetType().Name), value: '$source'"
            return $target.Clone()
        }
        
        $result = $target.Clone()
        foreach ($key in $source.Keys) {
            if ($result.ContainsKey($key) -and $result[$key] -is [hashtable] -and $source[$key] -is [hashtable]) {
                $result[$key] = $this.MergeHashtables($result[$key], $source[$key])
            } else {
                $result[$key] = $source[$key]
            }
        }
        return $result
    }

    [hashtable] ToHashtable() {
        return @{
            version = $this.Version
            analysis = $this.Analysis
            rules = $this.Rules
            autofix = $this.AutoFix
            suppressions = $this.Suppressions
            reporting = $this.Reporting
            ci = $this.CI
            webhooks = $this.Webhooks
            enterprise = $this.Enterprise
            hooks = $this.Hooks
            performance = $this.Performance
            integrations = $this.Integrations
            custom_rules = $this.CustomRules
        }
    }
}

function Import-PowerShieldConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$WorkspacePath = '.'
    )

    $config = [PowerShieldConfiguration]::new()

    # 1. Look for global config
    $homeDir = if ($IsWindows) { $env:USERPROFILE } else { $env:HOME }
    if ($homeDir) {
        $globalConfigPaths = @(
            (Join-Path $homeDir '.powershield.yml'),
            (Join-Path $homeDir '.powershield.yaml')
        )
        
        foreach ($path in $globalConfigPaths) {
            if (Test-Path $path) {
                $loaded = Read-ConfigFile -Path $path
                if ($loaded) {
                    Write-Verbose "Loaded global configuration from: $path"
                    $config.Merge($loaded)
                    break
                }
            }
        }
    }

    # 2. Look for project config
    $projectConfigPaths = @(
        (Join-Path $WorkspacePath '.powershield.yml'),
        (Join-Path $WorkspacePath '.powershield.yaml'),
        (Join-Path $WorkspacePath 'powershield.yml'),
        (Join-Path $WorkspacePath 'powershield.yaml')
    )

    foreach ($path in $projectConfigPaths) {
        if (Test-Path $path) {
            $loaded = Read-ConfigFile -Path $path
            if ($loaded) {
                Write-Verbose "Loaded project configuration from: $path"
                $config.Merge($loaded)
                break
            }
        }
    }

    # 3. Look for local config
    $localConfigPaths = @(
        (Join-Path $WorkspacePath '.powershield.local.yml'),
        (Join-Path $WorkspacePath '.powershield.local.yaml')
    )

    foreach ($path in $localConfigPaths) {
        if (Test-Path $path) {
            $loaded = Read-ConfigFile -Path $path
            if ($loaded) {
                Write-Verbose "Loaded local configuration from: $path"
                $config.Merge($loaded)
                break
            }
        }
    }

    return $config
}

function Read-ConfigFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    try {
        # Try to use powershell-yaml if available
        if ($script:yamlAvailable) {
            Import-Module powershell-yaml -ErrorAction Stop
            $content = Get-Content -Path $Path -Raw
            $config = ConvertFrom-Yaml -Yaml $content -ErrorAction Stop
            return $config
        } else {
            # Fallback: Simple YAML parsing for basic configs
            Write-Warning "powershell-yaml module not found. Using basic YAML parser. Install with: Install-Module powershell-yaml"
            return Read-SimpleYaml -Path $Path
        }
    } catch {
        Write-Warning "Failed to read configuration from ${Path}: $_"
        return $null
    }
}

function Read-SimpleYaml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    # Very basic YAML parser for simple key-value configs
    # This is a fallback and doesn't support all YAML features
    
    $lines = Get-Content -Path $Path
    $config = @{}
    $currentSection = $null

    foreach ($line in $lines) {
        # Skip comments and empty lines
        if ($line -match '^\s*#' -or $line -match '^\s*$') {
            continue
        }

        # Top-level keys
        if ($line -match '^([a-z_]+):\s*(.*)$') {
            $keyName = $matches[1]
            $value = $matches[2].Trim()
            
            if ($value -eq '') {
                # This is a section
                $currentSection = $keyName
                $config[$keyName] = @{}
            } else {
                # Simple value
                $config[$keyName] = $this.ParseYamlValue($value)
            }
        }
        # Nested keys
        elseif ($line -match '^\s+([a-z_]+):\s*(.*)$' -and $currentSection) {
            $keyName = $matches[1]
            $value = $matches[2].Trim()
            
            $config[$currentSection][$keyName] = $this.ParseYamlValue($value)
        }
    }

    return $config
}

function ParseYamlValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Value
    )
    
    # Try to parse value
    if ($Value -eq 'true') { return $true }
    elseif ($Value -eq 'false') { return $false }
    elseif ($Value -match '^\d+$') { return [int]$Value }
    elseif ($Value -match '^"(.+)"$') { return $matches[1] }
    else { return $Value }
}

function Export-PowerShieldConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PowerShieldConfiguration]$Configuration,

        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $hashtable = $Configuration.ToHashtable()

    if ($script:yamlAvailable) {
        try {
            Import-Module powershell-yaml -ErrorAction Stop
            $yaml = ConvertTo-Yaml -Data $hashtable
            $yaml | Out-File -FilePath $Path -Encoding UTF8
            Write-Host "Configuration saved to: $Path"
            return
        } catch {
            Write-Warning "Failed to use powershell-yaml: $_"
        }
    }

    # Fallback: Export as JSON if YAML not available
    $jsonPath = $Path -replace '\.ya?ml$', '.json'
    $hashtable | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host "Configuration saved to: $jsonPath (as JSON, install powershell-yaml for YAML support)"
}

function Test-PowerShieldConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PowerShieldConfiguration]$Configuration
    )

    $errors = @()

    # Validate version
    if ($Configuration.Version -ne '1.0') {
        $errors += "Invalid config version (expected '1.0')"
    }

    # Validate analysis settings
    if ($Configuration.Analysis.max_file_size -le 0) {
        $errors += "analysis.max_file_size must be positive"
    }
    if ($Configuration.Analysis.timeout_seconds -le 0) {
        $errors += "analysis.timeout_seconds must be positive"
    }

    # Validate autofix settings
    if ($Configuration.AutoFix.confidence_threshold -lt 0 -or $Configuration.AutoFix.confidence_threshold -gt 1) {
        $errors += "autofix.confidence_threshold must be between 0 and 1"
    }
    if ($Configuration.AutoFix.max_fixes -lt 0) {
        $errors += "autofix.max_fixes must be non-negative"
    }

    $validProviders = @('github-models', 'openai', 'azure', 'claude', 'template')
    if ($Configuration.AutoFix.provider -notin $validProviders) {
        $errors += "autofix.provider must be one of: $($validProviders -join ', ')"
    }

    # Validate suppression settings
    if ($Configuration.Suppressions.max_duration_days -lt 0) {
        $errors += "suppressions.max_duration_days must be non-negative"
    }

    # Validate CI settings
    if ($Configuration.CI.max_warnings -lt 0) {
        $errors += "ci.max_warnings must be non-negative"
    }

    return @{
        Valid = ($errors.Count -eq 0)
        Errors = $errors
    }
}

Export-ModuleMember -Function Import-PowerShieldConfiguration, Export-PowerShieldConfiguration, Test-PowerShieldConfiguration

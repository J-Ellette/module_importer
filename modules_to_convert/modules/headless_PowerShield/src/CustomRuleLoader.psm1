#Requires -Version 7.0

<#
.SYNOPSIS
    Custom rule loader for PowerShield Rule Marketplace & Community Plugins
.DESCRIPTION
    Loads YAML-based custom security rules and converts them to SecurityRule objects.
    Supports community rules, templates, and validation.
.NOTES
    Version: 1.0.0
    Author: PowerShield Project
#>

using namespace System.Management.Automation.Language
using namespace System.Collections.Generic

# Check if powershell-yaml module is available
$yamlAvailable = $null -ne (Get-Module -ListAvailable -Name 'powershell-yaml')

if (-not $yamlAvailable) {
    Write-Warning "powershell-yaml module not found. Install with: Install-Module powershell-yaml -Scope CurrentUser"
    Write-Warning "Custom YAML rules will not be available until the module is installed."
}

class CustomRuleDefinition {
    [string]$Id
    [string]$Name
    [string]$Description
    [string]$Severity
    [string]$Category
    [string[]]$CWE
    [string[]]$MitreAttack
    [string[]]$OWASP
    [array]$Patterns
    [string]$Remediation
    [string]$HelpUri
    [hashtable]$Metadata

    CustomRuleDefinition() {
        $this.Patterns = @()
        $this.CWE = @()
        $this.MitreAttack = @()
        $this.OWASP = @()
        $this.Metadata = @{}
    }

    [bool] Validate([ref]$errorMessages) {
        $errors = @()
        
        # Required fields
        if ([string]::IsNullOrWhiteSpace($this.Id)) {
            $errors += "Rule ID is required"
        }
        if ([string]::IsNullOrWhiteSpace($this.Name)) {
            $errors += "Rule name is required"
        }
        if ([string]::IsNullOrWhiteSpace($this.Severity)) {
            $errors += "Severity is required"
        }
        
        # Validate severity
        $validSeverities = @('Low', 'Medium', 'High', 'Critical')
        if ($this.Severity -and $this.Severity -notin $validSeverities) {
            $errors += "Invalid severity '$($this.Severity)'. Must be one of: $($validSeverities -join ', ')"
        }
        
        # Validate patterns
        if ($this.Patterns.Count -eq 0) {
            $errors += "At least one pattern is required"
        }
        
        foreach ($pattern in $this.Patterns) {
            if (-not $pattern.type) {
                $errors += "Pattern type is required"
            }
            
            $validTypes = @('command', 'regex', 'ast', 'parameter')
            if ($pattern.type -and $pattern.type -notin $validTypes) {
                $errors += "Invalid pattern type '$($pattern.type)'. Must be one of: $($validTypes -join ', ')"
            }
            
            # Validate required fields per pattern type
            switch ($pattern.type) {
                'command' {
                    if (-not $pattern.command) {
                        $errors += "Command pattern requires 'command' field"
                    }
                }
                'regex' {
                    if (-not $pattern.pattern) {
                        $errors += "Regex pattern requires 'pattern' field"
                    }
                    # Test regex validity
                    if ($pattern.pattern) {
                        try {
                            [void][regex]::new($pattern.pattern)
                        } catch {
                            $errors += "Invalid regex pattern: $($_.Exception.Message)"
                        }
                    }
                }
                'ast' {
                    if (-not $pattern.ast_type) {
                        $errors += "AST pattern requires 'ast_type' field"
                    }
                }
                'parameter' {
                    if (-not $pattern.command -or -not $pattern.parameter) {
                        $errors += "Parameter pattern requires 'command' and 'parameter' fields"
                    }
                }
            }
            
            if (-not $pattern.message) {
                $errors += "Pattern message is required"
            }
        }
        
        if ($errors.Count -gt 0) {
            $errorMessages.Value = $errors
            return $false
        }
        
        return $true
    }
}

class CustomRuleLoader {
    [string]$RulesDirectory
    [List[CustomRuleDefinition]]$LoadedRules
    [hashtable]$ValidationErrors

    CustomRuleLoader([string]$rulesDirectory) {
        $this.RulesDirectory = $rulesDirectory
        $this.LoadedRules = [List[CustomRuleDefinition]]::new()
        $this.ValidationErrors = @{}
    }

    [CustomRuleDefinition[]] LoadRulesFromDirectory() {
        if (-not (Test-Path $this.RulesDirectory)) {
            Write-Verbose "Rules directory not found: $($this.RulesDirectory)"
            return @()
        }

        $yamlFiles = Get-ChildItem -Path $this.RulesDirectory -Filter "*.yml" -Recurse -ErrorAction SilentlyContinue
        $yamlFiles += Get-ChildItem -Path $this.RulesDirectory -Filter "*.yaml" -Recurse -ErrorAction SilentlyContinue

        Write-Verbose "Found $($yamlFiles.Count) YAML rule files in $($this.RulesDirectory)"

        foreach ($file in $yamlFiles) {
            try {
                $rule = $this.LoadRuleFromFile($file.FullName)
                if ($rule) {
                    $this.LoadedRules.Add($rule)
                }
            } catch {
                Write-Warning "Failed to load rule from $($file.Name): $($_.Exception.Message)"
                $this.ValidationErrors[$file.Name] = $_.Exception.Message
            }
        }

        return $this.LoadedRules.ToArray()
    }

    [CustomRuleDefinition] LoadRuleFromFile([string]$filePath) {
        if (-not $script:yamlAvailable) {
            throw "powershell-yaml module is not installed. Cannot load YAML rules."
        }

        Write-Verbose "Loading rule from: $filePath"

        # Load YAML content
        $yamlContent = Get-Content -Path $filePath -Raw
        $yaml = ConvertFrom-Yaml -Yaml $yamlContent -ErrorAction Stop

        if (-not $yaml.rule) {
            throw "Invalid rule file: missing 'rule' root element"
        }

        # Create rule definition
        $ruleDef = [CustomRuleDefinition]::new()
        
        # Map YAML to rule definition
        if ($yaml.rule.id) { $ruleDef.Id = $yaml.rule.id }
        if ($yaml.rule.name) { $ruleDef.Name = $yaml.rule.name }
        if ($yaml.rule.description) { $ruleDef.Description = $yaml.rule.description }
        if ($yaml.rule.severity) { $ruleDef.Severity = $yaml.rule.severity }
        if ($yaml.rule.category) { $ruleDef.Category = $yaml.rule.category }
        if ($yaml.rule.remediation) { $ruleDef.Remediation = $yaml.rule.remediation }
        if ($yaml.rule.help_uri) { $ruleDef.HelpUri = $yaml.rule.help_uri }
        
        # Handle arrays
        if ($yaml.rule.cwe) {
            if ($yaml.rule.cwe -is [array]) {
                $ruleDef.CWE = $yaml.rule.cwe
            } else {
                $ruleDef.CWE = @($yaml.rule.cwe)
            }
        }
        
        if ($yaml.rule.mitre_attack) {
            if ($yaml.rule.mitre_attack -is [array]) {
                $ruleDef.MitreAttack = $yaml.rule.mitre_attack
            } else {
                $ruleDef.MitreAttack = @($yaml.rule.mitre_attack)
            }
        }
        
        if ($yaml.rule.owasp) {
            if ($yaml.rule.owasp -is [array]) {
                $ruleDef.OWASP = $yaml.rule.owasp
            } else {
                $ruleDef.OWASP = @($yaml.rule.owasp)
            }
        }
        
        # Handle patterns
        if ($yaml.rule.patterns) {
            $ruleDef.Patterns = $yaml.rule.patterns
        }
        
        # Handle metadata
        if ($yaml.rule.metadata) {
            $ruleDef.Metadata = $yaml.rule.metadata
        }

        # Validate rule
        $errors = $null
        if (-not $ruleDef.Validate([ref]$errors)) {
            $errorMsg = "Rule validation failed for $($ruleDef.Id): $($errors -join ', ')"
            throw $errorMsg
        }

        Write-Verbose "Successfully loaded rule: $($ruleDef.Id) - $($ruleDef.Name)"
        return $ruleDef
    }

    [object] ConvertToSecurityRule([CustomRuleDefinition]$ruleDef) {
        # Import SecuritySeverity enum if needed
        $severity = switch ($ruleDef.Severity) {
            'Critical' { 4 }
            'High' { 3 }
            'Medium' { 2 }
            'Low' { 1 }
            default { 2 }
        }

        # Create evaluator scriptblock
        $evaluator = $this.CreateEvaluatorFromPatterns($ruleDef)

        # Create SecurityRule (we'll need to load the class from the main module)
        # For now, return a hashtable that can be converted
        return @{
            Name = $ruleDef.Id
            Description = if ($ruleDef.Description) { $ruleDef.Description } else { $ruleDef.Name }
            Severity = $severity
            Evaluator = $evaluator
            Category = if ($ruleDef.Category) { $ruleDef.Category } else { 'CustomRule' }
            Tags = @('custom', 'community')
            CWE = $ruleDef.CWE
            MitreAttack = $ruleDef.MitreAttack
            OWASP = $ruleDef.OWASP
            HelpUri = $ruleDef.HelpUri
            Remediation = $ruleDef.Remediation
        }
    }

    [scriptblock] CreateEvaluatorFromPatterns([CustomRuleDefinition]$ruleDef) {
        # Create scriptblock that evaluates all patterns
        $patterns = $ruleDef.Patterns
        $ruleId = $ruleDef.Id
        $remediation = $ruleDef.Remediation

        $scriptblock = {
            param($Ast, $FilePath)
            $violations = @()
            
            foreach ($pattern in $using:patterns) {
                switch ($pattern.type) {
                    'command' {
                        # Find command invocations
                        $commands = $Ast.FindAll({
                            $args[0] -is [CommandAst] -and 
                            $args[0].GetCommandName() -eq $using:pattern.command
                        }, $true)
                        
                        foreach ($cmd in $commands) {
                            $violation = [PSCustomObject]@{
                                Name = $using:ruleId
                                Message = $pattern.message
                                Description = if ($using:remediation) { $using:remediation } else { $pattern.message }
                                Severity = $null  # Will be set by SecurityRule
                                LineNumber = $cmd.Extent.StartLineNumber
                                Code = $cmd.Extent.Text
                                FilePath = $FilePath
                                RuleId = $using:ruleId
                                Metadata = @{}
                                Fixes = @()
                                CodeFlows = @()
                            }
                            
                            # Add fix if specified
                            if ($pattern.fix) {
                                $violation.Fixes += @{
                                    description = $pattern.fix.description
                                    replacement = $pattern.fix.replacement
                                }
                            }
                            
                            $violations += $violation
                        }
                    }
                    
                    'regex' {
                        # Find regex pattern matches in script content
                        $scriptContent = Get-Content -Path $FilePath -Raw -ErrorAction SilentlyContinue
                        if ($scriptContent) {
                            $regex = [regex]::new($pattern.pattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
                            $matches = $regex.Matches($scriptContent)
                            
                            foreach ($match in $matches) {
                                # Calculate line number
                                $lineNumber = ($scriptContent.Substring(0, $match.Index) -split "`n").Count
                                
                                # Extract the line of code
                                $lines = $scriptContent -split "`n"
                                $codeLine = if ($lineNumber -le $lines.Count) { $lines[$lineNumber - 1] } else { $match.Value }
                                
                                $violation = [PSCustomObject]@{
                                    Name = $using:ruleId
                                    Message = $pattern.message
                                    Description = if ($using:remediation) { $using:remediation } else { $pattern.message }
                                    Severity = $null
                                    LineNumber = $lineNumber
                                    Code = $codeLine.Trim()
                                    FilePath = $FilePath
                                    RuleId = $using:ruleId
                                    Metadata = @{ MatchedText = $match.Value }
                                    Fixes = @()
                                    CodeFlows = @()
                                }
                                
                                $violations += $violation
                            }
                        }
                    }
                    
                    'ast' {
                        # Find specific AST node types
                        $astTypeName = $pattern.ast_type
                        $astType = $astTypeName -as [type]
                        
                        if (-not $astType) {
                            Write-Warning "Unknown AST type: $astTypeName"
                            continue
                        }
                        
                        $nodes = $Ast.FindAll({ $args[0].GetType().Name -eq $astTypeName }, $true)
                        
                        foreach ($node in $nodes) {
                            # Apply additional filters if specified
                            $matches = $true
                            if ($pattern.filter) {
                                # Evaluate filter condition
                                try {
                                    $filterScript = [scriptblock]::Create($pattern.filter)
                                    $matches = & $filterScript $node
                                } catch {
                                    Write-Warning "Filter evaluation failed: $_"
                                }
                            }
                            
                            if ($matches) {
                                $violation = [PSCustomObject]@{
                                    Name = $using:ruleId
                                    Message = $pattern.message
                                    Description = if ($using:remediation) { $using:remediation } else { $pattern.message }
                                    Severity = $null
                                    LineNumber = $node.Extent.StartLineNumber
                                    Code = $node.Extent.Text
                                    FilePath = $FilePath
                                    RuleId = $using:ruleId
                                    Metadata = @{}
                                    Fixes = @()
                                    CodeFlows = @()
                                }
                                
                                $violations += $violation
                            }
                        }
                    }
                    
                    'parameter' {
                        # Find command with specific parameter
                        $commands = $Ast.FindAll({
                            $args[0] -is [CommandAst] -and 
                            $args[0].GetCommandName() -eq $using:pattern.command
                        }, $true)
                        
                        foreach ($cmd in $commands) {
                            $hasParameter = $false
                            $paramValue = $null
                            
                            foreach ($element in $cmd.CommandElements) {
                                if ($element -is [CommandParameterAst] -and 
                                    $element.ParameterName -like "$($pattern.parameter)*") {
                                    $hasParameter = $true
                                    
                                    # Try to get parameter value
                                    $elementIndex = $cmd.CommandElements.IndexOf($element)
                                    if ($elementIndex -ge 0 -and $elementIndex + 1 -lt $cmd.CommandElements.Count) {
                                        $nextElement = $cmd.CommandElements[$elementIndex + 1]
                                        if ($nextElement -is [StringConstantExpressionAst]) {
                                            $paramValue = $nextElement.Value
                                        }
                                    }
                                    break
                                }
                            }
                            
                            # Check if value matches if specified
                            $matches = $hasParameter
                            if ($matches -and $pattern.value) {
                                if ($paramValue) {
                                    $matches = $paramValue -like $pattern.value
                                } else {
                                    $matches = $false
                                }
                            }
                            
                            if ($matches) {
                                $violation = [PSCustomObject]@{
                                    Name = $using:ruleId
                                    Message = $pattern.message
                                    Description = if ($using:remediation) { $using:remediation } else { $pattern.message }
                                    Severity = $null
                                    LineNumber = $cmd.Extent.StartLineNumber
                                    Code = $cmd.Extent.Text
                                    FilePath = $FilePath
                                    RuleId = $using:ruleId
                                    Metadata = @{ ParameterValue = $paramValue }
                                    Fixes = @()
                                    CodeFlows = @()
                                }
                                
                                $violations += $violation
                            }
                        }
                    }
                }
            }
            
            return $violations
        }
        
        return $scriptblock
    }
}

# Public functions

function Import-CustomRules {
    <#
    .SYNOPSIS
        Import custom rules from YAML files
    .PARAMETER RulesDirectory
        Path to directory containing custom rule YAML files
    .PARAMETER ValidationOnly
        Only validate rules without importing them
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RulesDirectory,
        
        [Parameter(Mandatory = $false)]
        [switch]$ValidationOnly
    )

    if (-not $script:yamlAvailable) {
        Write-Warning "powershell-yaml module is not installed. Install with: Install-Module powershell-yaml -Scope CurrentUser"
        return @()
    }

    # Import powershell-yaml module
    Import-Module powershell-yaml -ErrorAction Stop

    $loader = [CustomRuleLoader]::new($RulesDirectory)
    $rules = $loader.LoadRulesFromDirectory()

    if ($ValidationOnly) {
        return @{
            ValidRules = $rules
            Errors = $loader.ValidationErrors
            Count = $rules.Count
        }
    }

    Write-Verbose "Loaded $($rules.Count) custom rules from $RulesDirectory"
    return $rules
}

function ConvertTo-SecurityRule {
    <#
    .SYNOPSIS
        Convert custom rule definition to SecurityRule object
    .PARAMETER CustomRule
        CustomRuleDefinition object to convert
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [CustomRuleDefinition]$CustomRule
    )

    process {
        $loader = [CustomRuleLoader]::new("")
        return $loader.ConvertToSecurityRule($CustomRule)
    }
}

function Test-CustomRule {
    <#
    .SYNOPSIS
        Validate a custom rule definition
    .PARAMETER RuleFile
        Path to YAML rule file to validate
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RuleFile
    )

    if (-not $script:yamlAvailable) {
        Write-Error "powershell-yaml module is not installed. Install with: Install-Module powershell-yaml -Scope CurrentUser"
        return $false
    }

    # Import powershell-yaml module
    Import-Module powershell-yaml -ErrorAction Stop

    try {
        $loader = [CustomRuleLoader]::new((Split-Path $RuleFile -Parent))
        $rule = $loader.LoadRuleFromFile($RuleFile)
        
        Write-Host "✓ Rule validated successfully: $($rule.Id) - $($rule.Name)" -ForegroundColor Green
        Write-Host "  Severity: $($rule.Severity)" -ForegroundColor Cyan
        Write-Host "  Patterns: $($rule.Patterns.Count)" -ForegroundColor Cyan
        if ($rule.CWE) {
            Write-Host "  CWE: $($rule.CWE -join ', ')" -ForegroundColor Cyan
        }
        
        return $true
    } catch {
        Write-Host "✗ Rule validation failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function New-CustomRuleTemplate {
    <#
    .SYNOPSIS
        Generate a custom rule template
    .PARAMETER OutputPath
        Path where template should be created
    .PARAMETER RuleType
        Type of rule template to generate (command, regex, ast, parameter)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('command', 'regex', 'ast', 'parameter', 'comprehensive')]
        [string]$RuleType = 'command'
    )

    $templates = @{
        'command' = @'
# Custom PowerShield Rule - Command Detection
rule:
  id: "CustomRule001"
  name: "Detect Unsafe Command"
  description: "Detects usage of potentially unsafe PowerShell command"
  severity: "High"  # Low, Medium, High, Critical
  category: "Security"
  cwe: ["CWE-XYZ"]
  mitre_attack: ["T1059.001"]
  owasp: ["A01:2021"]
  help_uri: "https://example.com/rules/CustomRule001"
  
  patterns:
    - type: "command"
      command: "Invoke-UnsafeCommand"
      message: "Unsafe command detected"
      fix:
        description: "Use safe alternative"
        replacement: "Invoke-SafeCommand"
  
  remediation: |
    Use the safe alternative: Invoke-SafeCommand
    
    Example:
    # Unsafe
    Invoke-UnsafeCommand -Data $userInput
    
    # Safe
    Invoke-SafeCommand -Data $userInput
'@
        
        'regex' = @'
# Custom PowerShield Rule - Regex Pattern Detection
rule:
  id: "CustomRule002"
  name: "Detect Dangerous Pattern"
  description: "Detects dangerous code patterns using regex"
  severity: "Medium"
  category: "Security"
  
  patterns:
    - type: "regex"
      pattern: 'dangerous-pattern-\w+'
      message: "Dangerous pattern found"
  
  remediation: |
    Avoid using this dangerous pattern. Use the recommended approach instead.
'@
        
        'ast' = @'
# Custom PowerShield Rule - AST-based Detection
rule:
  id: "CustomRule003"
  name: "Detect Specific AST Node"
  description: "Detects specific AST node types with optional filtering"
  severity: "High"
  category: "Security"
  
  patterns:
    - type: "ast"
      ast_type: "InvokeMemberExpressionAst"
      filter: '$args[0].Member.Value -eq "UnsafeMethod"'
      message: "Unsafe method invocation detected"
  
  remediation: |
    Avoid using this unsafe method. Use alternative approaches.
'@
        
        'parameter' = @'
# Custom PowerShield Rule - Parameter Detection
rule:
  id: "CustomRule004"
  name: "Detect Unsafe Parameter"
  description: "Detects command with unsafe parameter usage"
  severity: "High"
  category: "Security"
  
  patterns:
    - type: "parameter"
      command: "Invoke-Command"
      parameter: "UnsafeOption"
      value: "Enabled"  # Optional: specific value to match
      message: "Command with unsafe parameter detected"
  
  remediation: |
    Do not use the -UnsafeOption parameter. It creates security risks.
'@
        
        'comprehensive' = @'
# Comprehensive Custom PowerShield Rule Template
rule:
  id: "CustomRule999"
  name: "Comprehensive Security Check"
  description: "Example rule demonstrating all pattern types and features"
  severity: "Critical"
  category: "Security"
  cwe: ["CWE-79", "CWE-89"]
  mitre_attack: ["T1059.001", "T1071.001"]
  owasp: ["A03:2021-Injection"]
  help_uri: "https://docs.powershield.io/rules/custom/comprehensive"
  
  patterns:
    # Command detection
    - type: "command"
      command: "Invoke-Expression"
      message: "Dangerous Invoke-Expression usage detected"
      fix:
        description: "Remove Invoke-Expression and use safe alternatives"
        replacement: "# REVIEW: Replace with safe code execution method"
    
    # Regex pattern matching
    - type: "regex"
      pattern: '\$\w+\s*=\s*["\']password["\']'
      message: "Hardcoded password string detected"
    
    # AST-based detection
    - type: "ast"
      ast_type: "TypeExpressionAst"
      filter: '$args[0].TypeName.Name -match "WebClient"'
      message: "Direct WebClient usage detected"
    
    # Parameter-based detection
    - type: "parameter"
      command: "New-Object"
      parameter: "ComObject"
      message: "COM object creation detected"
  
  remediation: |
    This rule detects multiple security issues:
    
    1. Avoid Invoke-Expression - use safer alternatives
    2. Never hardcode passwords - use SecureString
    3. Use HttpClient instead of WebClient
    4. Be cautious with COM objects
    
    For more information, visit the documentation.
  
  metadata:
    author: "Security Team"
    version: "1.0.0"
    tags: ["injection", "credentials", "network"]
'@
    }

    $template = $templates[$RuleType]
    
    if (-not $template) {
        Write-Error "Unknown rule type: $RuleType"
        return
    }

    # Ensure parent directory exists
    $parentDir = Split-Path $OutputPath -Parent
    if ($parentDir -and -not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }

    # Write template
    Set-Content -Path $OutputPath -Value $template -Encoding UTF8
    Write-Host "✓ Created custom rule template: $OutputPath" -ForegroundColor Green
    Write-Host "  Type: $RuleType" -ForegroundColor Cyan
    Write-Host "  Next: Edit the template and validate with: Test-CustomRule -RuleFile '$OutputPath'" -ForegroundColor Yellow
}

# Export functions
Export-ModuleMember -Function Import-CustomRules, ConvertTo-SecurityRule, Test-CustomRule, New-CustomRuleTemplate

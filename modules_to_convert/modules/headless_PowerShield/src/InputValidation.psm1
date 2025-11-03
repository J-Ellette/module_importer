#Requires -Version 7.0

<#
.SYNOPSIS
    Input validation and sanitization for PowerShield
.DESCRIPTION
    Provides comprehensive input validation and sanitization to protect PowerShield
    against malicious inputs, path traversal attacks, and injection vulnerabilities.
.NOTES
    Version: 1.7.0
    Author: PowerShield Project
    Security: This module is critical for PowerShield's own security posture
#>

class InputValidator {
    # Maximum allowed path depth to prevent excessive traversal
    static [int]$MaxPathDepth = 100
    
    # Maximum file size for configuration files (10MB)
    static [int]$MaxConfigFileSize = 10485760
    
    # Allowed file extensions for analysis
    static [string[]]$AllowedScriptExtensions = @('.ps1', '.psm1', '.psd1')
    
    # Regex patterns for validation
    static [regex]$SafePathPattern = [regex]::new('^[a-zA-Z0-9._\-/\\:]+$')
    static [regex]$PathTraversalPattern = [regex]::new('\.\.[/\\]')
    static [regex]$SafeFilenamePattern = [regex]::new('^[a-zA-Z0-9._\-]+$')
    
    <#
    .SYNOPSIS
        Validates and sanitizes a file path
    .DESCRIPTION
        Checks for path traversal attempts, validates path format, and ensures the path is safe to use
    .PARAMETER Path
        The file path to validate
    .PARAMETER MustExist
        If true, requires the path to exist
    .PARAMETER AllowDirectory
        If true, allows directory paths
    .RETURNS
        Validated and resolved absolute path
    #>
    static [string] ValidatePath([string]$Path, [bool]$MustExist = $false, [bool]$AllowDirectory = $false) {
        if ([string]::IsNullOrWhiteSpace($Path)) {
            throw [System.ArgumentException]::new("Path cannot be null or empty")
        }
        
        # Check for path traversal attempts
        if ([InputValidator]::PathTraversalPattern.IsMatch($Path)) {
            throw [System.Security.SecurityException]::new("Path traversal detected: $Path")
        }
        
        # Check path length
        if ($Path.Length -gt 260 -and -not $Path.StartsWith('\\?\')) {
            throw [System.ArgumentException]::new("Path exceeds maximum length: $Path")
        }
        
        # Resolve to absolute path
        try {
            $resolvedPath = [System.IO.Path]::GetFullPath($Path)
        }
        catch {
            throw [System.ArgumentException]::new("Invalid path format: $Path", $_.Exception)
        }
        
        # Check path depth
        $depth = ($resolvedPath -split '[/\\]').Count
        if ($depth -gt [InputValidator]::MaxPathDepth) {
            throw [System.Security.SecurityException]::new("Path depth exceeds maximum allowed: $depth")
        }
        
        # Validate existence if required
        if ($MustExist) {
            if ($AllowDirectory) {
                if (-not (Test-Path -Path $resolvedPath -PathType Any)) {
                    throw [System.IO.FileNotFoundException]::new("Path not found: $resolvedPath")
                }
            }
            else {
                if (-not (Test-Path -Path $resolvedPath -PathType Leaf)) {
                    throw [System.IO.FileNotFoundException]::new("File not found: $resolvedPath")
                }
            }
        }
        
        # Additional checks for existing paths
        if (Test-Path -Path $resolvedPath) {
            # Check if it's a directory when files are expected
            if (-not $AllowDirectory -and (Test-Path -Path $resolvedPath -PathType Container)) {
                throw [System.ArgumentException]::new("Expected file but got directory: $resolvedPath")
            }
            
            # Validate file extension for script files
            if (-not $AllowDirectory -and (Test-Path -Path $resolvedPath -PathType Leaf)) {
                $extension = [System.IO.Path]::GetExtension($resolvedPath)
                if ($extension -and -not ([InputValidator]::AllowedScriptExtensions -contains $extension)) {
                    Write-Warning "File extension $extension is not a standard PowerShell extension"
                }
            }
        }
        
        return $resolvedPath
    }
    
    <#
    .SYNOPSIS
        Validates a configuration file path and content
    .PARAMETER Path
        Path to configuration file
    .RETURNS
        Validated absolute path
    #>
    static [string] ValidateConfigFile([string]$Path) {
        $validatedPath = [InputValidator]::ValidatePath($Path, $true, $false)
        
        # Check file size
        $fileInfo = Get-Item -Path $validatedPath
        if ($fileInfo.Length -gt [InputValidator]::MaxConfigFileSize) {
            throw [System.Security.SecurityException]::new(
                "Configuration file exceeds maximum size: $($fileInfo.Length) bytes"
            )
        }
        
        # Validate file extension
        $extension = $fileInfo.Extension
        if ($extension -notin @('.yml', '.yaml', '.json')) {
            throw [System.ArgumentException]::new(
                "Invalid configuration file extension: $extension. Expected .yml, .yaml, or .json"
            )
        }
        
        return $validatedPath
    }
    
    <#
    .SYNOPSIS
        Sanitizes a string for safe logging
    .PARAMETER Input
        String to sanitize
    .RETURNS
        Sanitized string safe for logging
    #>
    static [string] SanitizeForLogging([string]$Input) {
        if ([string]::IsNullOrEmpty($Input)) {
            return $Input
        }
        
        # Remove potential ANSI escape sequences
        $sanitized = $Input -replace '\x1b\[[0-9;]*[a-zA-Z]', ''
        
        # Remove control characters except newline and tab
        $sanitized = $sanitized -replace '[^\x20-\x7E\r\n\t]', ''
        
        # Limit length for logging
        if ($sanitized.Length -gt 500) {
            $sanitized = $sanitized.Substring(0, 497) + "..."
        }
        
        return $sanitized
    }
    
    <#
    .SYNOPSIS
        Validates a severity level string
    .PARAMETER Severity
        Severity string to validate
    .RETURNS
        Validated severity string
    #>
    static [string] ValidateSeverity([string]$Severity) {
        $validSeverities = @('Low', 'Medium', 'High', 'Critical')
        
        if ([string]::IsNullOrWhiteSpace($Severity)) {
            throw [System.ArgumentException]::new("Severity cannot be null or empty")
        }
        
        if ($Severity -notin $validSeverities) {
            throw [System.ArgumentException]::new(
                "Invalid severity: $Severity. Must be one of: $($validSeverities -join ', ')"
            )
        }
        
        return $Severity
    }
    
    <#
    .SYNOPSIS
        Validates a numeric parameter is within allowed range
    .PARAMETER Value
        Numeric value to validate
    .PARAMETER Min
        Minimum allowed value
    .PARAMETER Max
        Maximum allowed value
    .PARAMETER ParameterName
        Name of parameter for error messages
    .RETURNS
        Validated numeric value
    #>
    static [int] ValidateNumericRange([int]$Value, [int]$Min, [int]$Max, [string]$ParameterName) {
        if ($Value -lt $Min -or $Value -gt $Max) {
            throw [System.ArgumentOutOfRangeException]::new(
                $ParameterName,
                $Value,
                "Value must be between $Min and $Max"
            )
        }
        
        return $Value
    }
    
    <#
    .SYNOPSIS
        Validates an email address format
    .PARAMETER Email
        Email address to validate
    .RETURNS
        Validated email address
    #>
    static [string] ValidateEmail([string]$Email) {
        if ([string]::IsNullOrWhiteSpace($Email)) {
            throw [System.ArgumentException]::new("Email cannot be null or empty")
        }
        
        # Basic email validation regex
        $emailPattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if ($Email -notmatch $emailPattern) {
            throw [System.ArgumentException]::new("Invalid email format: $Email")
        }
        
        return $Email.ToLowerInvariant()
    }
    
    <#
    .SYNOPSIS
        Validates a URL format
    .PARAMETER Url
        URL to validate
    .PARAMETER RequireHttps
        If true, requires HTTPS scheme
    .RETURNS
        Validated URL as Uri object
    #>
    static [System.Uri] ValidateUrl([string]$Url, [bool]$RequireHttps = $false) {
        if ([string]::IsNullOrWhiteSpace($Url)) {
            throw [System.ArgumentException]::new("URL cannot be null or empty")
        }
        
        try {
            $uri = [System.Uri]::new($Url)
            
            if ($uri.Scheme -notin @('http', 'https')) {
                throw [System.ArgumentException]::new("URL must use HTTP or HTTPS scheme: $Url")
            }
            
            if ($RequireHttps -and $uri.Scheme -ne 'https') {
                throw [System.Security.SecurityException]::new("URL must use HTTPS: $Url")
            }
            
            return $uri
        }
        catch [System.UriFormatException] {
            throw [System.ArgumentException]::new("Invalid URL format: $Url", $_.Exception)
        }
    }
    
    <#
    .SYNOPSIS
        Validates a regex pattern is safe and valid
    .PARAMETER Pattern
        Regex pattern to validate
    .RETURNS
        Validated regex pattern
    #>
    static [string] ValidateRegexPattern([string]$Pattern) {
        if ([string]::IsNullOrWhiteSpace($Pattern)) {
            throw [System.ArgumentException]::new("Regex pattern cannot be null or empty")
        }
        
        # Check pattern length
        if ($Pattern.Length -gt 1000) {
            throw [System.ArgumentException]::new("Regex pattern exceeds maximum length")
        }
        
        # Try to compile the regex
        try {
            $null = [regex]::new($Pattern, [System.Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(1))
        }
        catch {
            throw [System.ArgumentException]::new("Invalid regex pattern: $Pattern", $_.Exception)
        }
        
        return $Pattern
    }
    
    <#
    .SYNOPSIS
        Sanitizes user input to prevent injection attacks
    .PARAMETER Input
        User input to sanitize
    .PARAMETER AllowedCharacters
        Regex pattern of allowed characters
    .RETURNS
        Sanitized input
    #>
    static [string] SanitizeUserInput([string]$Input, [string]$AllowedCharacters = '^[a-zA-Z0-9._\-]+$') {
        if ([string]::IsNullOrWhiteSpace($Input)) {
            return $Input
        }
        
        # Remove dangerous characters
        $sanitized = $Input -replace '[;&|<>`$(){}[\]\\]', ''
        
        # Apply allowed character filter if provided
        if (-not [string]::IsNullOrWhiteSpace($AllowedCharacters)) {
            if ($sanitized -notmatch $AllowedCharacters) {
                throw [System.ArgumentException]::new(
                    "Input contains disallowed characters: $Input"
                )
            }
        }
        
        return $sanitized
    }
    
    <#
    .SYNOPSIS
        Creates a secure temporary file
    .PARAMETER Extension
        File extension (optional)
    .RETURNS
        Path to secure temporary file
    #>
    static [string] CreateSecureTempFile([string]$Extension = '.tmp') {
        $tempPath = [System.IO.Path]::GetTempPath()
        $fileName = [System.IO.Path]::GetRandomFileName()
        
        if ($Extension -and -not $Extension.StartsWith('.')) {
            $Extension = ".$Extension"
        }
        
        $fileName = [System.IO.Path]::ChangeExtension($fileName, $Extension)
        $fullPath = Join-Path -Path $tempPath -ChildPath $fileName
        
        # Create the file with restricted permissions
        try {
            $null = New-Item -Path $fullPath -ItemType File -Force
            
            # On Windows, set file permissions to current user only
            $isWindows = [System.Environment]::OSVersion.Platform -eq 'Win32NT' -or [System.Environment]::OSVersion.Platform -eq 'Win32Windows'
            $isUnix = [System.Environment]::OSVersion.Platform -eq 'Unix'
            
            if ($isWindows) {
                $acl = Get-Acl -Path $fullPath
                $acl.SetAccessRuleProtection($true, $false)
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
                    "FullControl",
                    "Allow"
                )
                $acl.SetAccessRule($accessRule)
                Set-Acl -Path $fullPath -AclObject $acl
            }
            elseif ($isUnix) {
                # Set permissions to 600 (user read/write only)
                & chmod 600 $fullPath
            }
        }
        catch {
            throw [System.IO.IOException]::new("Failed to create secure temporary file", $_.Exception)
        }
        
        return $fullPath
    }
}

# Export the class methods as functions for easier use
function Test-SecurePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [switch]$MustExist,
        
        [Parameter(Mandatory = $false)]
        [switch]$AllowDirectory
    )
    
    return [InputValidator]::ValidatePath($Path, $MustExist.IsPresent, $AllowDirectory.IsPresent)
}

function Test-SecureConfigFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    return [InputValidator]::ValidateConfigFile($Path)
}

function ConvertTo-SafeLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Input
    )
    
    return [InputValidator]::SanitizeForLogging($Input)
}

# Export both the class and the wrapper functions
Export-ModuleMember -Function Test-SecurePath, Test-SecureConfigFile, ConvertTo-SafeLog

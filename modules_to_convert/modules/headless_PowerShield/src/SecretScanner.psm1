#Requires -Version 7.0

<#
.SYNOPSIS
    Advanced secret detection module for PowerShield
.DESCRIPTION
    Detects various types of secrets and credentials in PowerShell scripts including
    AWS keys, Azure keys, GitHub tokens, API keys, private keys, connection strings, etc.
#>

using namespace System.Collections.Generic
using namespace System.Text.RegularExpressions

# Secret types enum
enum SecretType {
    AWSAccessKey
    AWSSecretKey
    AzureStorageKey
    AzureSubscriptionKey
    GitHubPAT
    GitHubOAuthToken
    GitHubFineGrainedPAT
    GitHubAppToken
    APIKey
    PrivateKeyPEM
    PrivateKeySSH
    PrivateKeyRSA
    DatabaseConnectionString
    OAuthToken
    OAuthClientSecret
    CryptocurrencyWallet
    GenericSecret
}

# Secret detection result
class SecretDetection {
    [string]$Type
    [string]$Value
    [int]$LineNumber
    [int]$ColumnNumber
    [string]$Context
    [double]$Confidence
    [string]$Entropy
    [hashtable]$Metadata
    
    SecretDetection([string]$type, [string]$value, [int]$line, [int]$column, [double]$confidence) {
        $this.Type = $type
        $this.Value = $value
        $this.LineNumber = $line
        $this.ColumnNumber = $column
        $this.Confidence = $confidence
        $this.Metadata = @{}
    }
}

class SecretScanner {
    [hashtable]$Patterns
    [hashtable]$Configuration
    [string[]]$AllowedSecrets  # Hashes of known safe values
    
    SecretScanner() {
        $this.Initialize()
    }
    
    [void] Initialize() {
        $this.Configuration = @{
            minEntropyThreshold = 3.5
            minLength = 16
            maxLength = 512
            detectPartialMatches = $true
            caseSensitive = $true
        }
        
        $this.AllowedSecrets = @()
        $this.InitializePatterns()
    }
    
    [void] InitializePatterns() {
        $this.Patterns = @{
            # AWS Credentials
            'AWSAccessKey' = @{
                Regex = 'AKIA[0-9A-Z]{16}'
                Description = 'AWS Access Key ID'
                MinEntropy = 3.0
                Severity = 'Critical'
            }
            'AWSSecretKey' = @{
                Regex = '(?i)aws.{0,20}secret.{0,20}[=:]\s*[''"]?([A-Za-z0-9/+=]{40})[''"]?'
                Description = 'AWS Secret Access Key'
                MinEntropy = 4.5
                Severity = 'Critical'
            }
            
            # Azure Credentials
            'AzureStorageKey' = @{
                Regex = '(?i)DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=([A-Za-z0-9+/]{88}==);'
                Description = 'Azure Storage Account Key'
                MinEntropy = 4.0
                Severity = 'Critical'
            }
            'AzureSubscriptionKey' = @{
                Regex = '(?i)subscription[-_]?key[''"\s:=]+([a-f0-9]{32})'
                Description = 'Azure Subscription Key'
                MinEntropy = 3.5
                Severity = 'Critical'
            }
            
            # GitHub Tokens
            'GitHubPAT' = @{
                Regex = 'ghp_[0-9a-zA-Z]{36}'
                Description = 'GitHub Personal Access Token'
                MinEntropy = 3.5
                Severity = 'Critical'
            }
            'GitHubOAuthToken' = @{
                Regex = 'gho_[0-9a-zA-Z]{36}'
                Description = 'GitHub OAuth Token'
                MinEntropy = 3.5
                Severity = 'Critical'
            }
            'GitHubFineGrainedPAT' = @{
                Regex = 'github_pat_[0-9a-zA-Z_]{82}'
                Description = 'GitHub Fine-Grained Personal Access Token'
                MinEntropy = 3.5
                Severity = 'Critical'
            }
            'GitHubAppToken' = @{
                Regex = '(ghu|ghs)_[0-9a-zA-Z]{36}'
                Description = 'GitHub App Token'
                MinEntropy = 3.5
                Severity = 'Critical'
            }
            
            # Generic API Keys
            'APIKeyHeader' = @{
                Regex = '(?i)(api[_-]?key|apikey|x-api-key)[''"\s:=]+([a-zA-Z0-9_\-]{20,})'
                Description = 'Generic API Key'
                MinEntropy = 3.0
                Severity = 'High'
            }
            'BearerToken' = @{
                Regex = 'Bearer\s+[A-Za-z0-9\-._~+/]+=*'
                Description = 'Bearer Token'
                MinEntropy = 3.5
                Severity = 'High'
            }
            
            # Private Keys
            'PrivateKeyPEM' = @{
                Regex = '-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----'
                Description = 'PEM Private Key'
                MinEntropy = 0.0  # Don't check entropy for PEM keys
                Severity = 'Critical'
            }
            'SSHPrivateKey' = @{
                Regex = '-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----'
                Description = 'OpenSSH Private Key'
                MinEntropy = 0.0
                Severity = 'Critical'
            }
            'RSAPrivateKey' = @{
                Regex = '-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+RSA\s+PRIVATE\s+KEY-----'
                Description = 'RSA Private Key'
                MinEntropy = 0.0
                Severity = 'Critical'
            }
            'EC Privatekey' = @{
                Regex = '-----BEGIN\s+EC\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+EC\s+PRIVATE\s+KEY-----'
                Description = 'EC Private Key'
                MinEntropy = 0.0
                Severity = 'Critical'
            }
            
            # Database Connection Strings
            'SQLServerConnectionString' = @{
                Regex = '(?i)(Server|Data Source)=.+?(;|$).*(Password|Pwd)=([^;]+)'
                Description = 'SQL Server Connection String with Password'
                MinEntropy = 2.0
                Severity = 'Critical'
            }
            'PostgreSQLConnectionString' = @{
                Regex = '(?i)postgres(ql)?://[^:]+:([^@]+)@'
                Description = 'PostgreSQL Connection String with Password'
                MinEntropy = 2.0
                Severity = 'Critical'
            }
            'MySQLConnectionString' = @{
                Regex = '(?i)mysql://[^:]+:([^@]+)@'
                Description = 'MySQL Connection String with Password'
                MinEntropy = 2.0
                Severity = 'Critical'
            }
            'MongoDBConnectionString' = @{
                Regex = '(?i)mongodb(\+srv)?://[^:]+:([^@]+)@'
                Description = 'MongoDB Connection String with Password'
                MinEntropy = 2.0
                Severity = 'Critical'
            }
            
            # OAuth Tokens
            'OAuthClientSecret' = @{
                Regex = '(?i)(client[_-]?secret|oauth[_-]?secret)[''"\s:=]+([a-zA-Z0-9_\-]{20,})'
                Description = 'OAuth Client Secret'
                MinEntropy = 3.0
                Severity = 'Critical'
            }
            'OAuthRefreshToken' = @{
                Regex = '(?i)(refresh[_-]?token)[''"\s:=]+([a-zA-Z0-9_\-\.]{20,})'
                Description = 'OAuth Refresh Token'
                MinEntropy = 3.0
                Severity = 'High'
            }
            
            # Cryptocurrency Wallets
            'BitcoinPrivateKey' = @{
                Regex = '[5KL][1-9A-HJ-NP-Za-km-z]{50,51}'
                Description = 'Bitcoin Private Key (WIF)'
                MinEntropy = 4.0
                Severity = 'Critical'
            }
            'EthereumPrivateKey' = @{
                Regex = '0x[a-fA-F0-9]{64}'
                Description = 'Ethereum Private Key'
                MinEntropy = 3.5
                Severity = 'Critical'
            }
            
            # Slack Tokens
            'SlackToken' = @{
                Regex = 'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}'
                Description = 'Slack Token'
                MinEntropy = 3.0
                Severity = 'High'
            }
            'SlackWebhook' = @{
                Regex = 'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'
                Description = 'Slack Webhook URL'
                MinEntropy = 0.0
                Severity = 'High'
            }
            
            # Stripe Keys
            'StripeAPIKey' = @{
                Regex = 'sk_live_[0-9a-zA-Z]{24,}'
                Description = 'Stripe API Key (Live)'
                MinEntropy = 3.0
                Severity = 'Critical'
            }
            'StripeTestKey' = @{
                Regex = 'sk_test_[0-9a-zA-Z]{24,}'
                Description = 'Stripe API Key (Test)'
                MinEntropy = 3.0
                Severity = 'Medium'
            }
            
            # Twilio Credentials
            'TwilioAccountSID' = @{
                Regex = 'AC[a-z0-9]{32}'
                Description = 'Twilio Account SID'
                MinEntropy = 2.5
                Severity = 'Medium'
            }
            'TwilioAuthToken' = @{
                Regex = '(?i)twilio.{0,20}auth[_-]?token[''"\s:=]+([a-z0-9]{32})'
                Description = 'Twilio Auth Token'
                MinEntropy = 3.0
                Severity = 'High'
            }
            
            # Google Cloud
            'GoogleAPIKey' = @{
                Regex = 'AIza[0-9A-Za-z_\-]{35}'
                Description = 'Google API Key'
                MinEntropy = 3.0
                Severity = 'High'
            }
            'GoogleOAuthClientSecret' = @{
                Regex = '(?i)client_secret[''"\s:]+([a-zA-Z0-9_\-]{24,})'
                Description = 'Google OAuth Client Secret'
                MinEntropy = 3.0
                Severity = 'Critical'
            }
            
            # JWT Tokens
            'JWTToken' = @{
                Regex = 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
                Description = 'JWT Token'
                MinEntropy = 3.0
                Severity = 'Medium'
            }
        }
    }
    
    <#
    .SYNOPSIS
        Calculate Shannon entropy of a string
    #>
    [double] CalculateEntropy([string]$text) {
        if ([string]::IsNullOrEmpty($text)) {
            return 0.0
        }
        
        [hashtable]$frequencies = @{}
        foreach ($char in $text.ToCharArray()) {
            if ($frequencies.ContainsKey($char)) {
                $frequencies[$char]++
            } else {
                $frequencies[$char] = 1
            }
        }
        
        [double]$entropy = 0.0
        [int]$length = $text.Length
        
        foreach ($count in $frequencies.Values) {
            [double]$probability = $count / $length
            $entropy -= $probability * [Math]::Log($probability, 2)
        }
        
        return [Math]::Round($entropy, 2)
    }
    
    <#
    .SYNOPSIS
        Check if a value is in the allowed secrets list
    #>
    [bool] IsAllowedSecret([string]$value) {
        [string]$hash = [System.Convert]::ToBase64String(
            [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($value)
            )
        )
        
        return ($this.AllowedSecrets -contains $hash)
    }
    
    <#
    .SYNOPSIS
        Scan content for secrets
    #>
    [SecretDetection[]] ScanContent([string]$content, [string]$filePath) {
        [SecretDetection[]]$detections = @()
        [string[]]$lines = $content -split "`n"
        
        for ([int]$lineIndex = 0; $lineIndex -lt $lines.Count; $lineIndex++) {
            [string]$line = $lines[$lineIndex]
            [int]$lineNumber = $lineIndex + 1
            
            # Skip comments (but still scan for secrets in them with lower priority)
            [bool]$isComment = $line.TrimStart() -match '^\s*#'
            
            foreach ($patternName in $this.Patterns.Keys) {
                [object]$patternInfo = $this.Patterns[$patternName]
                [string]$regexPattern = $patternInfo.Regex
                [double]$minEntropy = $patternInfo.MinEntropy
                
                try {
                    [System.Text.RegularExpressions.MatchCollection]$matches = [Regex]::Matches($line, $regexPattern, [System.Text.RegularExpressions.RegexOptions]::None)
                    
                    foreach ($match in $matches) {
                        [string]$matchValue = $match.Value
                        
                        # Skip if in allowed list
                        if ($this.IsAllowedSecret($matchValue)) {
                            continue
                        }
                        
                        # Calculate entropy
                        [double]$entropy = $this.CalculateEntropy($matchValue)
                        
                        # Check entropy threshold (skip for patterns with minEntropy = 0)
                        if ($minEntropy -gt 0 -and $entropy -lt $minEntropy) {
                            continue
                        }
                        
                        # Calculate confidence
                        [double]$confidence = 0.9
                        if ($isComment) {
                            $confidence = 0.7
                        }
                        if ($entropy -gt 4.5) {
                            $confidence = [Math]::Min(1.0, $confidence + 0.1)
                        }
                        
                        [SecretDetection]$detection = [SecretDetection]::new(
                            $patternName,
                            $matchValue,
                            $lineNumber,
                            $match.Index,
                            $confidence
                        )
                        
                        $detection.Entropy = "$entropy"
                        $detection.Context = $line.Trim()
                        $detection.Metadata = @{
                            Description = $patternInfo.Description
                            Severity = $patternInfo.Severity
                            FilePath = $filePath
                            IsInComment = $isComment
                        }
                        
                        $detections += $detection
                    }
                } catch {
                    # Skip patterns that fail to match
                    Write-Verbose "Pattern $patternName failed: $($_.Exception.Message)"
                }
            }
        }
        
        return $detections
    }
}

# Export functions
function New-SecretScanner {
    [CmdletBinding()]
    param()
    
    return [SecretScanner]::new()
}

function Invoke-SecretScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ScriptPath,
        
        [Parameter()]
        [string[]]$AllowedSecrets = @()
    )
    
    if (-not (Test-Path $ScriptPath)) {
        throw "File not found: $ScriptPath"
    }
    
    [string]$content = Get-Content -Path $ScriptPath -Raw
    [SecretScanner]$scanner = [SecretScanner]::new()
    $scanner.AllowedSecrets = $AllowedSecrets
    
    [SecretDetection[]]$detections = $scanner.ScanContent($content, $ScriptPath)
    
    return @{
        FilePath = $ScriptPath
        SecretsFound = $detections.Count
        Detections = $detections
        Summary = @{
            Critical = ($detections | Where-Object { $_.Metadata.Severity -eq 'Critical' }).Count
            High = ($detections | Where-Object { $_.Metadata.Severity -eq 'High' }).Count
            Medium = ($detections | Where-Object { $_.Metadata.Severity -eq 'Medium' }).Count
        }
    }
}

function Invoke-WorkspaceSecretScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WorkspacePath,
        
        [Parameter()]
        [string[]]$AllowedSecrets = @(),
        
        [Parameter()]
        [string[]]$Extensions = @('*.ps1', '*.psm1', '*.psd1', '*.json', '*.yml', '*.yaml', '*.txt', '*.md')
    )
    
    if (-not (Test-Path $WorkspacePath)) {
        throw "Path not found: $WorkspacePath"
    }
    
    [SecretScanner]$scanner = [SecretScanner]::new()
    $scanner.AllowedSecrets = $AllowedSecrets
    
    [System.Collections.ArrayList]$allDetections = @()
    [int]$filesScanned = 0
    
    foreach ($ext in $Extensions) {
        [array]$files = Get-ChildItem -Path $WorkspacePath -Filter $ext -Recurse -File
        
        foreach ($file in $files) {
            $filesScanned++
            Write-Progress -Activity "Scanning for secrets" -Status "File: $($file.Name)" -PercentComplete (($filesScanned / ($files.Count * $Extensions.Count)) * 100)
            
            [string]$content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
            if ($content) {
                [SecretDetection[]]$fileDetections = $scanner.ScanContent($content, $file.FullName)
                $allDetections.AddRange($fileDetections)
            }
        }
    }
    
    Write-Progress -Activity "Scanning for secrets" -Completed
    
    return @{
        WorkspacePath = $WorkspacePath
        FilesScanned = $filesScanned
        SecretsFound = $allDetections.Count
        Detections = $allDetections
        Summary = @{
            Critical = ($allDetections | Where-Object { $_.Metadata.Severity -eq 'Critical' }).Count
            High = ($allDetections | Where-Object { $_.Metadata.Severity -eq 'High' }).Count
            Medium = ($allDetections | Where-Object { $_.Metadata.Severity -eq 'Medium' }).Count
        }
    }
}

Export-ModuleMember -Function @(
    'New-SecretScanner',
    'Invoke-SecretScan',
    'Invoke-WorkspaceSecretScan'
)

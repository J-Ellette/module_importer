#Requires -Version 7.0

<#
.SYNOPSIS
    Suppression Comment Parser for PowerShield
.DESCRIPTION
    Parses and evaluates suppression comments in PowerShell scripts.
    Supports various suppression formats with justifications and expiry dates.
.NOTES
    Version: 1.0.0
    Author: PowerShield Project
#>

# Suppression comment formats:
# POWERSHIELD-SUPPRESS-NEXT: RuleId - Justification
# POWERSHIELD-SUPPRESS: RuleId - Justification (inline)
# POWERSHIELD-SUPPRESS-START: RuleId - Justification
# POWERSHIELD-SUPPRESS-END
# POWERSHIELD-SUPPRESS-NEXT: RuleId - Justification (YYYY-MM-DD)

class Suppression {
    [string]$RuleId
    [string]$Justification
    [datetime]$ExpiryDate
    [int]$StartLine
    [int]$EndLine
    [string]$Type  # 'next', 'inline', 'block'
    [string]$FilePath
    [bool]$IsExpired
    [bool]$IsPermanent

    Suppression([string]$ruleId, [string]$justification, [int]$line, [string]$type) {
        $this.RuleId = $ruleId
        $this.Justification = $justification
        $this.StartLine = $line
        $this.EndLine = $line
        $this.Type = $type
        $this.IsExpired = $false
        $this.IsPermanent = $true  # No expiry date means permanent
    }

    [void] SetExpiryDate([datetime]$date) {
        $this.ExpiryDate = $date
        $this.IsPermanent = $false
        $this.IsExpired = (Get-Date) -gt $date
    }

    [void] SetEndLine([int]$line) {
        $this.EndLine = $line
    }

    [bool] AppliesToLine([int]$line) {
        return $line -ge $this.StartLine -and $line -le $this.EndLine
    }

    [bool] AppliesToRule([string]$ruleId) {
        return $this.RuleId -eq $ruleId -or $this.RuleId -eq 'all'
    }
}

class SuppressionParser {
    [System.Collections.Generic.List[Suppression]]$Suppressions
    [bool]$RequireJustification
    [int]$MaxDurationDays
    [bool]$AllowPermanent

    SuppressionParser([bool]$requireJustification, [int]$maxDurationDays, [bool]$allowPermanent) {
        $this.Suppressions = [System.Collections.Generic.List[Suppression]]::new()
        $this.RequireJustification = $requireJustification
        $this.MaxDurationDays = $maxDurationDays
        $this.AllowPermanent = $allowPermanent
    }

    [void] ParseFile([string]$filePath) {
        if (-not (Test-Path $filePath)) {
            throw "File not found: $filePath"
        }

        $lines = Get-Content $filePath -ErrorAction Stop
        $currentBlock = $null

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            $lineNumber = $i + 1

            # Check for POWERSHIELD-SUPPRESS-START
            if ($line -match '#\s*POWERSHIELD-SUPPRESS-START:\s*(.+)') {
                $parsed = $this.ParseSuppressionComment($matches[1], $lineNumber, 'block')
                if ($parsed) {
                    $parsed.FilePath = $filePath
                    $currentBlock = $parsed
                }
                continue
            }

            # Check for POWERSHIELD-SUPPRESS-END
            if ($line -match '#\s*POWERSHIELD-SUPPRESS-END') {
                if ($currentBlock) {
                    $currentBlock.SetEndLine($lineNumber - 1)
                    $this.Suppressions.Add($currentBlock)
                    $currentBlock = $null
                }
                continue
            }

            # Check for POWERSHIELD-SUPPRESS-NEXT
            if ($line -match '#\s*POWERSHIELD-SUPPRESS-NEXT:\s*(.+)') {
                $parsed = $this.ParseSuppressionComment($matches[1], $lineNumber, 'next')
                if ($parsed) {
                    $parsed.FilePath = $filePath
                    $parsed.SetEndLine($lineNumber + 1)  # Apply to next line
                    $this.Suppressions.Add($parsed)
                }
                continue
            }

            # Check for inline POWERSHIELD-SUPPRESS
            if ($line -match '#\s*POWERSHIELD-SUPPRESS:\s*(.+)') {
                $parsed = $this.ParseSuppressionComment($matches[1], $lineNumber, 'inline')
                if ($parsed) {
                    $parsed.FilePath = $filePath
                    $this.Suppressions.Add($parsed)
                }
                continue
            }
        }

        # If block suppression was not closed, close it at end of file
        if ($currentBlock) {
            $currentBlock.SetEndLine($lines.Count)
            $this.Suppressions.Add($currentBlock)
        }
    }

    [Suppression] ParseSuppressionComment([string]$comment, [int]$lineNumber, [string]$type) {
        # Parse format: RuleId - Justification (YYYY-MM-DD)
        # or: RuleId - Justification
        # or: RuleId

        $comment = $comment.Trim()

        # Extract expiry date if present
        $expiryDate = $null
        if ($comment -match '\((\d{4}-\d{2}-\d{2})\)\s*$') {
            try {
                $expiryDate = [datetime]::ParseExact($matches[1], 'yyyy-MM-dd', $null)
                $comment = $comment -replace '\(\d{4}-\d{2}-\d{2}\)\s*$', ''
                $comment = $comment.Trim()
            } catch {
                Write-Warning "Invalid date format in suppression at line $lineNumber"
            }
        }

        # Split into RuleId and Justification
        $parts = $comment -split '\s*-\s*', 2
        $ruleId = $parts[0].Trim()
        $justification = if ($parts.Count -gt 1) { $parts[1].Trim() } else { '' }

        # Validate
        if (-not $ruleId) {
            Write-Warning "Suppression at line $lineNumber missing rule ID"
            return $null
        }

        if ($this.RequireJustification -and -not $justification) {
            Write-Warning "Suppression at line $lineNumber missing required justification"
            return $null
        }

        if ($expiryDate -and -not $this.AllowPermanent) {
            # Validate expiry date is within max duration
            $maxDate = (Get-Date).AddDays($this.MaxDurationDays)
            if ($expiryDate -gt $maxDate) {
                Write-Warning "Suppression at line $lineNumber exceeds maximum duration of $($this.MaxDurationDays) days"
                $expiryDate = $maxDate
            }
        } elseif (-not $expiryDate -and -not $this.AllowPermanent) {
            Write-Warning "Suppression at line $lineNumber is permanent but permanent suppressions are not allowed"
            # Auto-set expiry to max duration
            $expiryDate = (Get-Date).AddDays($this.MaxDurationDays)
        }

        $suppression = [Suppression]::new($ruleId, $justification, $lineNumber, $type)
        if ($expiryDate) {
            $suppression.SetExpiryDate($expiryDate)
        }

        return $suppression
    }

    [bool] IsSuppressed([string]$ruleId, [int]$lineNumber) {
        foreach ($suppression in $this.Suppressions) {
            if ($suppression.AppliesToRule($ruleId) -and $suppression.AppliesToLine($lineNumber)) {
                if ($suppression.IsExpired) {
                    Write-Warning "Suppression for $ruleId at line $lineNumber has expired on $($suppression.ExpiryDate.ToString('yyyy-MM-dd'))"
                    return $false
                }
                return $true
            }
        }
        return $false
    }

    [Suppression[]] GetExpiredSuppressions() {
        return @($this.Suppressions | Where-Object { $_.IsExpired })
    }

    [Suppression[]] GetExpiringSuppressions([int]$daysWarning) {
        $warnDate = (Get-Date).AddDays($daysWarning)
        return @($this.Suppressions | Where-Object { 
            -not $_.IsPermanent -and -not $_.IsExpired -and $_.ExpiryDate -le $warnDate 
        })
    }

    [hashtable] GenerateSuppressionReport() {
        $total = $this.Suppressions.Count
        $expired = @($this.Suppressions | Where-Object { $_.IsExpired }).Count
        $expiring = @($this.GetExpiringSuppressions(30)).Count
        $permanent = @($this.Suppressions | Where-Object { $_.IsPermanent }).Count

        $byRule = @{}
        foreach ($suppression in $this.Suppressions) {
            if (-not $byRule.ContainsKey($suppression.RuleId)) {
                $byRule[$suppression.RuleId] = 0
            }
            $byRule[$suppression.RuleId]++
        }

        return @{
            TotalSuppressions = $total
            ExpiredCount = $expired
            ExpiringSoonCount = $expiring
            PermanentCount = $permanent
            ByRule = $byRule
            Suppressions = $this.Suppressions
        }
    }

    [string] GenerateSuppressionMarkdown() {
        $report = $this.GenerateSuppressionReport()
        
        $markdown = "# PowerShield Suppression Report`n`n"
        $markdown += "## Summary`n`n"
        $markdown += "- **Total Suppressions**: $($report.TotalSuppressions)`n"
        $markdown += "- **Expired**: $($report.ExpiredCount)`n"
        $markdown += "- **Expiring Soon (30 days)**: $($report.ExpiringSoonCount)`n"
        $markdown += "- **Permanent**: $($report.PermanentCount)`n`n"

        if ($report.ByRule.Count -gt 0) {
            $markdown += "## Suppressions by Rule`n`n"
            $markdown += "| Rule ID | Count |`n"
            $markdown += "|---------|-------|`n"
            foreach ($rule in $report.ByRule.Keys | Sort-Object) {
                $markdown += "| $rule | $($report.ByRule[$rule]) |`n"
            }
            $markdown += "`n"
        }

        if ($report.ExpiredCount -gt 0) {
            $markdown += "## ⚠️ Expired Suppressions`n`n"
            $expired = $this.GetExpiredSuppressions()
            foreach ($suppression in $expired) {
                $markdown += "- **$($suppression.RuleId)** in $($suppression.FilePath):$($suppression.StartLine)`n"
                $markdown += "  - Expired: $($suppression.ExpiryDate.ToString('yyyy-MM-dd'))`n"
                $markdown += "  - Justification: $($suppression.Justification)`n`n"
            }
        }

        if ($report.ExpiringSoonCount -gt 0) {
            $markdown += "## 🔔 Expiring Soon`n`n"
            $expiring = $this.GetExpiringSuppressions(30)
            foreach ($suppression in $expiring) {
                $markdown += "- **$($suppression.RuleId)** in $($suppression.FilePath):$($suppression.StartLine)`n"
                $markdown += "  - Expires: $($suppression.ExpiryDate.ToString('yyyy-MM-dd'))`n"
                $markdown += "  - Justification: $($suppression.Justification)`n`n"
            }
        }

        return $markdown
    }
}

# Export functions
function New-SuppressionParser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [bool]$RequireJustification = $true,

        [Parameter(Mandatory=$false)]
        [int]$MaxDurationDays = 90,

        [Parameter(Mandatory=$false)]
        [bool]$AllowPermanent = $false
    )

    return [SuppressionParser]::new($RequireJustification, $MaxDurationDays, $AllowPermanent)
}

function Test-Suppression {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [SuppressionParser]$Parser,

        [Parameter(Mandatory=$true)]
        [string]$RuleId,

        [Parameter(Mandatory=$true)]
        [int]$LineNumber
    )

    return $Parser.IsSuppressed($RuleId, $LineNumber)
}

function Get-SuppressionReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [SuppressionParser]$Parser,

        [Parameter(Mandatory=$false)]
        [switch]$AsMarkdown
    )

    if ($AsMarkdown) {
        return $Parser.GenerateSuppressionMarkdown()
    } else {
        return $Parser.GenerateSuppressionReport()
    }
}

Export-ModuleMember -Function New-SuppressionParser, Test-Suppression, Get-SuppressionReport

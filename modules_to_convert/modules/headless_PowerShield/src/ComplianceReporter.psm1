#Requires -Version 7.0

<#
.SYNOPSIS
    Compliance reporting module for PowerShield
.DESCRIPTION
    Maps security violations to various compliance frameworks and generates
    compliance reports, gap analysis, and audit evidence.
.NOTES
    Version: 1.0.0
    Author: PowerShield Project
#>

# Compliance framework mapping class
class ComplianceFramework {
    [string]$Name
    [string]$Version
    [hashtable]$ControlMappings
    
    ComplianceFramework([string]$name, [string]$version) {
        $this.Name = $name
        $this.Version = $version
        $this.ControlMappings = @{}
    }
}

# Compliance control class
class ComplianceControl {
    [string]$ControlId
    [string]$Framework
    [string]$Category
    [string]$Description
    [string[]]$MappedRules
    [string]$Status  # Compliant, NonCompliant, PartiallyCompliant, NotApplicable
    [int]$ViolationCount
    [object[]]$Violations
    
    ComplianceControl([string]$controlId, [string]$framework, [string]$category, [string]$description) {
        $this.ControlId = $controlId
        $this.Framework = $framework
        $this.Category = $category
        $this.Description = $description
        $this.MappedRules = @()
        $this.Status = "NotApplicable"
        $this.ViolationCount = 0
        $this.Violations = @()
    }
}

# Initialize compliance framework mappings
function Initialize-ComplianceFrameworks {
    <#
    .SYNOPSIS
        Initializes all supported compliance frameworks with rule mappings
    #>
    [CmdletBinding()]
    param()
    
    $frameworks = @{}
    
    # NIST Cybersecurity Framework
    $nist = [ComplianceFramework]::new("NIST Cybersecurity Framework", "1.1")
    $nist.ControlMappings = @{
        "PR.AC-4" = @{
            Category = "Protect - Access Control"
            Description = "Access permissions and authorizations are managed"
            Rules = @("CredentialExposure", "AzurePowerShellCredentialLeaks", "CredentialHarvesting")
        }
        "PR.AC-7" = @{
            Category = "Protect - Access Control"
            Description = "Users, devices, and other assets are authenticated"
            Rules = @("CertificateValidation", "CertificateStoreManipulation", "AzureEntraIDPrivilegedOperations")
        }
        "PR.DS-1" = @{
            Category = "Protect - Data Security"
            Description = "Data-at-rest is protected"
            Rules = @("InsecureHashAlgorithms", "AzureEncryptionBypass")
        }
        "PR.DS-2" = @{
            Category = "Protect - Data Security"
            Description = "Data-in-transit is protected"
            Rules = @("UnsafeHTTPUsage", "TLSVersionDowngrade")
        }
        "DE.CM-4" = @{
            Category = "Detect - Continuous Monitoring"
            Description = "Malicious code is detected"
            Rules = @("PowerShellObfuscation", "DownloadCradle", "AMSIEvasion", "ETWEvasion")
        }
        "DE.CM-7" = @{
            Category = "Detect - Continuous Monitoring"
            Description = "Monitoring for unauthorized personnel, connections, devices"
            Rules = @("LateralMovement", "PSRemotingUnsafe", "RemoteExecution")
        }
        "RS.AN-3" = @{
            Category = "Respond - Analysis"
            Description = "Forensics are performed"
            Rules = @("ScriptBlockLoggingDisabled", "AzureLoggingDisabled")
        }
    }
    $frameworks["NIST"] = $nist
    
    # CIS PowerShell Security Benchmark
    $cis = [ComplianceFramework]::new("CIS PowerShell Security Benchmark", "1.0")
    $cis.ControlMappings = @{
        "1.1" = @{
            Category = "Execution Policy"
            Description = "Ensure PowerShell execution policy is configured"
            Rules = @("ExecutionPolicyBypass")
        }
        "2.1" = @{
            Category = "Script Block Logging"
            Description = "Enable PowerShell script block logging"
            Rules = @("ScriptBlockLoggingDisabled")
        }
        "2.2" = @{
            Category = "Transcription"
            Description = "Enable PowerShell transcription logging"
            Rules = @("TranscriptionLoggingDisabled")
        }
        "3.1" = @{
            Category = "Remoting"
            Description = "Configure PowerShell remoting securely"
            Rules = @("PSRemotingUnsafe", "RemoteExecution")
        }
        "4.1" = @{
            Category = "Version Control"
            Description = "Disable PowerShell v2"
            Rules = @("PowerShellVersion2")
        }
        "5.1" = @{
            Category = "Credential Management"
            Description = "Protect credentials in scripts"
            Rules = @("CredentialExposure", "ConvertToSecureStringPlainText")
        }
    }
    $frameworks["CIS"] = $cis
    
    # OWASP Top 10
    $owasp = [ComplianceFramework]::new("OWASP Top 10", "2021")
    $owasp.ControlMappings = @{
        "A01" = @{
            Category = "Broken Access Control"
            Description = "Restrictions on authenticated users not properly enforced"
            Rules = @("UnsafeFilePermissions", "RegistryPermissionsBypass")
        }
        "A02" = @{
            Category = "Cryptographic Failures"
            Description = "Failures related to cryptography leading to sensitive data exposure"
            Rules = @("InsecureHashAlgorithms", "AzureEncryptionBypass")
        }
        "A03" = @{
            Category = "Injection"
            Description = "Injection flaws such as SQL, command, LDAP injection"
            Rules = @("CommandInjection", "SQLInjection", "LDAPInjection")
        }
        "A05" = @{
            Category = "Security Misconfiguration"
            Description = "Missing or insecure configurations"
            Rules = @("CertificateValidation", "ExecutionPolicyBypass", "AzurePolicyAndCompliance")
        }
        "A07" = @{
            Category = "Identification and Authentication Failures"
            Description = "Failures in authentication mechanisms"
            Rules = @("CredentialExposure", "AzurePowerShellCredentialLeaks")
        }
        "A09" = @{
            Category = "Security Logging and Monitoring Failures"
            Description = "Insufficient logging and monitoring"
            Rules = @("ScriptBlockLoggingDisabled", "AzureLoggingDisabled")
        }
    }
    $frameworks["OWASP"] = $owasp
    
    # SOC 2
    $soc2 = [ComplianceFramework]::new("SOC 2", "Type II")
    $soc2.ControlMappings = @{
        "CC6.1" = @{
            Category = "Common Criteria - Logical and Physical Access Controls"
            Description = "Restrict logical access to system resources"
            Rules = @("CredentialExposure", "UnsafeFilePermissions")
        }
        "CC6.6" = @{
            Category = "Common Criteria - Logical and Physical Access Controls"
            Description = "Protect data in transit and at rest"
            Rules = @("InsecureHashAlgorithms", "UnsafeHTTPUsage", "AzureEncryptionBypass")
        }
        "CC6.7" = @{
            Category = "Common Criteria - Logical and Physical Access Controls"
            Description = "Restrict access to confidential information"
            Rules = @("CredentialExposure", "AzurePowerShellCredentialLeaks")
        }
        "CC7.2" = @{
            Category = "Common Criteria - System Operations"
            Description = "Detect security events and incidents"
            Rules = @("PowerShellObfuscation", "DownloadCradle", "CredentialHarvesting")
        }
        "CC7.3" = @{
            Category = "Common Criteria - System Operations"
            Description = "Evaluate security events to determine if incidents occurred"
            Rules = @("ScriptBlockLoggingDisabled", "AzureLoggingDisabled")
        }
    }
    $frameworks["SOC2"] = $soc2
    
    # PCI-DSS
    $pci = [ComplianceFramework]::new("PCI-DSS", "4.0")
    $pci.ControlMappings = @{
        "3.5" = @{
            Category = "Protect Stored Cardholder Data"
            Description = "Protect encryption keys"
            Rules = @("CredentialExposure", "CertificateStoreManipulation")
        }
        "4.1" = @{
            Category = "Protect Cardholder Data with Strong Cryptography"
            Description = "Use strong cryptography for transmission"
            Rules = @("UnsafeHTTPUsage", "TLSVersionDowngrade", "InsecureHashAlgorithms")
        }
        "8.2" = @{
            Category = "Identify Users and Authenticate Access"
            Description = "Ensure proper user authentication"
            Rules = @("CredentialExposure", "ConvertToSecureStringPlainText")
        }
        "10.2" = @{
            Category = "Log and Monitor All Access"
            Description = "Implement automated audit trails"
            Rules = @("ScriptBlockLoggingDisabled", "AzureLoggingDisabled")
        }
    }
    $frameworks["PCI-DSS"] = $pci
    
    # HIPAA
    $hipaa = [ComplianceFramework]::new("HIPAA Security Rule", "2023")
    $hipaa.ControlMappings = @{
        "164.308(a)(3)" = @{
            Category = "Workforce Security"
            Description = "Implement procedures to authorize access to ePHI"
            Rules = @("CredentialExposure", "UnsafeFilePermissions")
        }
        "164.308(a)(5)(ii)(C)" = @{
            Category = "Security Awareness and Training"
            Description = "Implement procedures for login monitoring"
            Rules = @("ScriptBlockLoggingDisabled")
        }
        "164.312(a)(2)(iv)" = @{
            Category = "Technical Safeguards - Access Control"
            Description = "Implement encryption and decryption"
            Rules = @("InsecureHashAlgorithms", "AzureEncryptionBypass")
        }
        "164.312(e)(1)" = @{
            Category = "Technical Safeguards - Transmission Security"
            Description = "Implement technical security measures for electronic communications"
            Rules = @("UnsafeHTTPUsage", "TLSVersionDowngrade")
        }
        "164.312(e)(2)(II)" = @{
            Category = "Technical Safeguards - Transmission Security"
            Description = "Implement encryption of ePHI in transit"
            Rules = @("UnsafeHTTPUsage", "InsecureHashAlgorithms")
        }
    }
    $frameworks["HIPAA"] = $hipaa
    
    return $frameworks
}

function Get-ComplianceStatus {
    <#
    .SYNOPSIS
        Evaluates compliance status based on analysis results
    .PARAMETER AnalysisResult
        The analysis result object from PowerShield
    .PARAMETER Framework
        Compliance framework to evaluate (NIST, CIS, OWASP, SOC2, PCI-DSS, HIPAA, All)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$AnalysisResult,
        
        [Parameter()]
        [ValidateSet('NIST', 'CIS', 'OWASP', 'SOC2', 'PCI-DSS', 'HIPAA', 'All')]
        [string]$Framework = 'All'
    )
    
    $frameworks = Initialize-ComplianceFrameworks
    
    # Extract all violations
    $allViolations = @()
    foreach ($fileResult in $AnalysisResult.Results) {
        if ($fileResult.Violations) {
            $allViolations += $fileResult.Violations
        }
    }
    
    # Group violations by rule
    $violationsByRule = @{}
    foreach ($violation in $allViolations) {
        if (-not $violationsByRule.ContainsKey($violation.RuleId)) {
            $violationsByRule[$violation.RuleId] = @()
        }
        $violationsByRule[$violation.RuleId] += $violation
    }
    
    $results = @{}
    
    $frameworksToProcess = if ($Framework -eq 'All') {
        $frameworks.Keys
    } else {
        @($Framework)
    }
    
    foreach ($fwName in $frameworksToProcess) {
        $fw = $frameworks[$fwName]
        $controls = @()
        
        foreach ($controlId in $fw.ControlMappings.Keys) {
            $mapping = $fw.ControlMappings[$controlId]
            $control = [ComplianceControl]::new(
                $controlId,
                $fw.Name,
                $mapping.Category,
                $mapping.Description
            )
            $control.MappedRules = $mapping.Rules
            
            # Check for violations
            $controlViolations = @()
            foreach ($rule in $mapping.Rules) {
                if ($violationsByRule.ContainsKey($rule)) {
                    $controlViolations += $violationsByRule[$rule]
                }
            }
            
            $control.Violations = $controlViolations
            $control.ViolationCount = $controlViolations.Count
            
            # Determine status
            if ($controlViolations.Count -eq 0) {
                $control.Status = "Compliant"
            } elseif ($controlViolations.Count -le 2) {
                $control.Status = "PartiallyCompliant"
            } else {
                $control.Status = "NonCompliant"
            }
            
            $controls += $control
        }
        
        $results[$fwName] = @{
            Framework = $fw.Name
            Version = $fw.Version
            Controls = $controls
            TotalControls = $controls.Count
            CompliantControls = ($controls | Where-Object { $_.Status -eq 'Compliant' }).Count
            PartiallyCompliantControls = ($controls | Where-Object { $_.Status -eq 'PartiallyCompliant' }).Count
            NonCompliantControls = ($controls | Where-Object { $_.Status -eq 'NonCompliant' }).Count
            CompliancePercentage = if ($controls.Count -gt 0) {
                [math]::Round((($controls | Where-Object { $_.Status -eq 'Compliant' }).Count / $controls.Count) * 100, 2)
            } else { 0 }
        }
    }
    
    return $results
}

function Export-ComplianceDashboard {
    <#
    .SYNOPSIS
        Exports a compliance dashboard report
    .PARAMETER ComplianceStatus
        Compliance status from Get-ComplianceStatus
    .PARAMETER OutputPath
        Path to save the dashboard
    .PARAMETER Format
        Output format (markdown, html, json)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$ComplianceStatus,
        
        [Parameter(Mandatory)]
        [string]$OutputPath,
        
        [Parameter()]
        [ValidateSet('markdown', 'html', 'json')]
        [string]$Format = 'markdown'
    )
    
    switch ($Format) {
        'markdown' {
            $report = Generate-ComplianceDashboardMarkdown -ComplianceStatus $ComplianceStatus
            $report | Out-File -FilePath $OutputPath -Encoding UTF8
        }
        'json' {
            $ComplianceStatus | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
        }
        'html' {
            $report = Generate-ComplianceDashboardHTML -ComplianceStatus $ComplianceStatus
            $report | Out-File -FilePath $OutputPath -Encoding UTF8
        }
    }
    
    Write-Host "Compliance dashboard exported to: $OutputPath" -ForegroundColor Green
}

function Generate-ComplianceDashboardMarkdown {
    param($ComplianceStatus)
    
    $report = @"
# PowerShield Compliance Dashboard

Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

## Executive Summary

"@

    foreach ($fwName in $ComplianceStatus.Keys) {
        $fw = $ComplianceStatus[$fwName]
        $report += @"

### $($fw.Framework) - $($fw.Version)

- **Total Controls**: $($fw.TotalControls)
- **Compliant**: $($fw.CompliantControls) ($(if($fw.TotalControls -gt 0){[math]::Round(($fw.CompliantControls/$fw.TotalControls)*100,1)}else{0})%)
- **Partially Compliant**: $($fw.PartiallyCompliantControls)
- **Non-Compliant**: $($fw.NonCompliantControls)
- **Overall Compliance**: $($fw.CompliancePercentage)%

"@
    }
    
    $report += "`n## Detailed Findings`n"
    
    foreach ($fwName in $ComplianceStatus.Keys) {
        $fw = $ComplianceStatus[$fwName]
        $report += "`n### $($fw.Framework)`n"
        
        # Show non-compliant controls first
        $nonCompliantControls = $fw.Controls | Where-Object { $_.Status -eq 'NonCompliant' }
        if ($nonCompliantControls.Count -gt 0) {
            $report += "`n#### ❌ Non-Compliant Controls`n"
            foreach ($control in $nonCompliantControls) {
                $report += "`n**$($control.ControlId)**: $($control.Category)`n"
                $report += "$($control.Description)`n"
                $report += "- Violations: $($control.ViolationCount)`n"
                $report += "- Affected Rules: $($control.MappedRules -join ', ')`n"
            }
        }
        
        # Show partially compliant
        $partialControls = $fw.Controls | Where-Object { $_.Status -eq 'PartiallyCompliant' }
        if ($partialControls.Count -gt 0) {
            $report += "`n#### ⚠️ Partially Compliant Controls`n"
            foreach ($control in $partialControls) {
                $report += "`n**$($control.ControlId)**: $($control.Category)`n"
                $report += "- Violations: $($control.ViolationCount)`n"
            }
        }
    }
    
    return $report
}

function Generate-ComplianceDashboardHTML {
    param($ComplianceStatus)
    
    $summaryRows = ""
    foreach ($fwName in $ComplianceStatus.Keys) {
        $fw = $ComplianceStatus[$fwName]
        $statusColor = if ($fw.CompliancePercentage -ge 90) { "#28a745" } 
                       elseif ($fw.CompliancePercentage -ge 70) { "#ffc107" } 
                       else { "#dc3545" }
        
        $summaryRows += @"
        <tr>
            <td>$($fw.Framework)</td>
            <td>$($fw.Version)</td>
            <td>$($fw.TotalControls)</td>
            <td style="color: #28a745;">$($fw.CompliantControls)</td>
            <td style="color: #ffc107;">$($fw.PartiallyCompliantControls)</td>
            <td style="color: #dc3545;">$($fw.NonCompliantControls)</td>
            <td style="color: $statusColor; font-weight: bold;">$($fw.CompliancePercentage)%</td>
        </tr>
"@
    }
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>PowerShield Compliance Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #3498db; color: white; font-weight: bold; }
        tr:hover { background-color: #f5f5f5; }
        .compliant { color: #28a745; }
        .partial { color: #ffc107; }
        .noncompliant { color: #dc3545; }
        .timestamp { color: #7f8c8d; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ PowerShield Compliance Dashboard</h1>
        <p class="timestamp">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        
        <h2>Executive Summary</h2>
        <table>
            <thead>
                <tr>
                    <th>Framework</th>
                    <th>Version</th>
                    <th>Total Controls</th>
                    <th>Compliant</th>
                    <th>Partially Compliant</th>
                    <th>Non-Compliant</th>
                    <th>Compliance %</th>
                </tr>
            </thead>
            <tbody>
                $summaryRows
            </tbody>
        </table>
    </div>
</body>
</html>
"@
    
    return $html
}

function Export-GapAnalysis {
    <#
    .SYNOPSIS
        Exports a gap analysis report identifying compliance gaps
    .PARAMETER ComplianceStatus
        Compliance status from Get-ComplianceStatus
    .PARAMETER OutputPath
        Path to save the gap analysis report
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$ComplianceStatus,
        
        [Parameter(Mandatory)]
        [string]$OutputPath
    )
    
    $report = @"
# PowerShield Gap Analysis Report

Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

## Purpose
This report identifies gaps in compliance with various security frameworks and provides
recommendations for remediation.

"@

    foreach ($fwName in $ComplianceStatus.Keys) {
        $fw = $ComplianceStatus[$fwName]
        $report += "`n## $($fw.Framework) - $($fw.Version)`n"
        $report += "`n**Current Compliance**: $($fw.CompliancePercentage)%`n"
        
        $gaps = $fw.Controls | Where-Object { $_.Status -ne 'Compliant' }
        
        if ($gaps.Count -eq 0) {
            $report += "`n✓ No gaps identified. Fully compliant with this framework.`n"
        } else {
            $report += "`n### Identified Gaps ($($gaps.Count) controls)`n"
            
            foreach ($control in $gaps) {
                $report += "`n#### $($control.ControlId): $($control.Category)`n"
                $report += "**Description**: $($control.Description)`n"
                $report += "**Status**: $($control.Status)`n"
                $report += "**Violations**: $($control.ViolationCount)`n"
                $report += "**Affected Rules**: $($control.MappedRules -join ', ')`n"
                
                $report += "`n**Remediation Steps**:`n"
                $report += "1. Review and address the following security violations:`n"
                
                foreach ($violation in ($control.Violations | Select-Object -First 5)) {
                    $report += "   - [$($violation.Severity)] $($violation.RuleId) in $($violation.FilePath):$($violation.LineNumber)`n"
                }
                
                if ($control.ViolationCount -gt 5) {
                    $report += "   - ... and $($control.ViolationCount - 5) more violations`n"
                }
                
                $report += "2. Implement security controls to prevent recurrence`n"
                $report += "3. Update security policies and procedures`n"
                $report += "4. Re-run PowerShield analysis to verify compliance`n`n"
            }
        }
    }
    
    $report | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Gap analysis report exported to: $OutputPath" -ForegroundColor Green
}

function Export-AuditEvidence {
    <#
    .SYNOPSIS
        Exports audit evidence for compliance verification
    .PARAMETER AnalysisResult
        The analysis result object
    .PARAMETER ComplianceStatus
        Compliance status from Get-ComplianceStatus
    .PARAMETER OutputPath
        Path to save the audit evidence package
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$AnalysisResult,
        
        [Parameter(Mandatory)]
        [object]$ComplianceStatus,
        
        [Parameter(Mandatory)]
        [string]$OutputPath
    )
    
    $evidence = @{
        GeneratedAt = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssZ')
        AnalysisSummary = @{
            TotalFiles = $AnalysisResult.TotalFiles
            TotalViolations = $AnalysisResult.TotalViolations
            SeverityBreakdown = $AnalysisResult.Summary
        }
        ComplianceStatus = $ComplianceStatus
        AuditTrail = @{
            ToolName = "PowerShield"
            ToolVersion = "1.2.0"
            AnalysisDate = (Get-Date).ToString('yyyy-MM-dd')
            Auditor = if ($env:USER) { $env:USER } elseif ($env:USERNAME) { $env:USERNAME } else { "Automated" }
        }
    }
    
    $evidence | ConvertTo-Json -Depth 20 | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Audit evidence exported to: $OutputPath" -ForegroundColor Green
}

# Export module members
Export-ModuleMember -Function @(
    'Initialize-ComplianceFrameworks',
    'Get-ComplianceStatus',
    'Export-ComplianceDashboard',
    'Export-GapAnalysis',
    'Export-AuditEvidence'
)

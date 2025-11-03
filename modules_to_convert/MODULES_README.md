# CIV-ARCOS Code Scanning Modules

A collection of 38 code scanning modules for security, compliance, vulnerability detection, quality assessment, and regulatory standards.

## Overview

CIV-ARCOS provides 38 specialized scanning modules, each inspired by industry-standard security and compliance frameworks. All modules follow the same pattern: scan repository code, analyze findings, assign a quality score (0-100%), and generate detailed reports with actionable recommendations.

## Module Categories

### Core Scanners (4 modules)

1. **Security Scanner** (SCAP-inspired)
2. **Compliance Scanner** (STIG-inspired)
3. **Vulnerability Scanner** (ACAS/Nessus-inspired)
4. **Quality Scanner** (BSI IT-Grundschutz-inspired)

### Supply Chain & SBOM (2 modules)

5. **Supply Chain Security Scanner** - Software supply chain security assessment
6. **SBOM Scanner** - Software Bill of Materials compliance

### Government & Defense Standards (7 modules)

7. **ATO Scanner** - Authority to Operate readiness
8. **DEF STAN Scanner** - UK defense software standards (DEF STAN 00-970)
9. **MIL-STD Scanner** - Military software documentation (MIL-STD-498)
10. **CMMC Scanner** - Cybersecurity Maturity Model Certification
11. **Cyber Exchange Scanner** - DoD Cyber Exchange compliance
12. **HACMS Scanner** - High-Assurance Cyber Military Systems
13. **Game Warden Scanner** - DevSecOps platform security

### Compliance & Certifications (5 modules)

14. **SOC 2 Scanner** - SOC 2 Type II trust services
15. **ISO 27001 Scanner** - ISO 27001 information security
16. **FedRAMP Scanner** - Federal cloud authorization
17. **CSA STAR Scanner** - Cloud Security Alliance certification
18. **Global Compliance Scanner** - Multi-jurisdiction regulatory compliance

### Cloud & Infrastructure (1 module)

19. **Cloud Compliance Scanner** - AWS/Azure/GCP compliance

### Development & Quality (5 modules)

20. **CASE Tools Scanner** - Computer-Aided Software Engineering
21. **Verification & Validation Scanner** - V&V processes
22. **Configuration Management Scanner** - Configuration management
23. **Architecture Scanner** - System design and architecture
24. **Mathematical Analysis Scanner** - Mathematical and algorithmic analysis

### Analysis & Testing (4 modules)

25. **Statistical Analysis Scanner** - Code metrics and statistical analysis
26. **AI Testing Scanner** - AI/ML model testing and characterization
27. **SafeDocs Scanner** - Safe document processing security
28. **V-SPELLs Scanner** - Legacy software security verification

### Security & Cryptography (2 modules)

29. **Cryptographic Validation Scanner** - Cryptographic algorithm validation
30. **Personnel Security Scanner** - Personnel security and clearance tracking

### Metadata & Documentation (3 modules)

31. **Metadata Management Scanner** - Resource metadata management
32. **Quality Management Scanner** - Quality management system
33. **Digital Government Scanner** - Government digital services

### Enterprise & Asset Management (5 modules)

34. **RegScale Scanner** - Compliance as code automation
35. **ARMATURE Scanner** - Accreditation and certification automation
36. **EAM Scanner** - Enterprise asset management
37. **Asset Tracking Scanner** - Government asset tracking
38. **Dynamics Scanner** - Microsoft 365 Dynamics for Government

## Features

- **Automated Scanning**: Scan repositories for security, compliance, vulnerability, and quality issues
- **Grading System**: Each module assigns a score (0-100%) and letter grade (A-F)
- **Detailed Reports**: Generate comprehensive reports with strengths, weaknesses, and recommendations
- **Multiple Formats**: Export reports in text, markdown, or JSON format
- **Modular Design**: Each scanner runs independently or as part of a comprehensive scan

## Installation

```bash
# Clone the repository
git clone https://github.com/J-Ellette/CIV-ARCOS.git
cd CIV-ARCOS

# No additional dependencies required - uses Python standard library
```

## Usage

### Command Line Interface

Run individual scanners:

```bash
# Core scanners
python scan.py security /path/to/repo
python scan.py compliance /path/to/repo
python scan.py vulnerability /path/to/repo
python scan.py quality /path/to/repo

# Government & defense
python scan.py cmmc /path/to/repo
python scan.py fedramp /path/to/repo
python scan.py ato /path/to/repo
python scan.py mil_std /path/to/repo

# Compliance & certifications
python scan.py soc2 /path/to/repo
python scan.py iso27001 /path/to/repo

# Supply chain
python scan.py sbom /path/to/repo
python scan.py supply_chain /path/to/repo

# Cloud
python scan.py cloud_compliance /path/to/repo

# Run all scanners
python scan.py all /path/to/repo
```

### Options

```bash
# Specify output directory
python scan.py all /path/to/repo --output reports/

# Choose report format (text, markdown, or json)
python scan.py security /path/to/repo --format markdown

# Full example
python scan.py all . --output ./scan_reports --format json
```

## Scanning Modules

### Core Security & Quality Scanners

#### Security Scanner
**Based on**: SCAP (Security Content Automation Protocol)

**Detects**:
- Hard-coded passwords, API keys, and secrets
- SQL injection vulnerabilities
- Command injection vulnerabilities
- Weak cryptographic practices
- Insecure random number generation
- Insecure file operations

**Grading**:
- **A (90-100%)**: Excellent security with minimal/no issues
- **B (80-89%)**: Good security with minor issues
- **C (70-79%)**: Satisfactory with some security concerns
- **D (60-69%)**: Below average with significant issues
- **F (0-59%)**: Failing - critical security vulnerabilities

#### Compliance Scanner
**Based on**: STIG (Security Technical Implementation Guide)

**Checks**:
- Required documentation (README, LICENSE)
- Recommended documentation (CONTRIBUTING, CHANGELOG, etc.)
- Code structure and organization
- Configuration file security
- Dependency management

**Grading**:
- Scores based on compliance with documentation and structure standards
- Bonus points for recommended files
- Penalties for insecure configurations

#### Vulnerability Scanner
**Based on**: ACAS/Nessus Professional

**Identifies**:
- Known CVEs in Python and JavaScript dependencies
- Outdated packages with security vulnerabilities
- Deprecated packages
- Dependency management issues

**Grading**:
- Severity-weighted scoring (Critical > High > Medium)
- Penalties based on vulnerabilities per dependency ratio

#### Quality Scanner
**Based on**: BSI IT-Grundschutz

**Assesses**:
- Code complexity (function length, nesting depth)
- Documentation quality (comments, docstrings)
- Code organization
- Maintainability indicators

**Grading**:
- Documentation (30%): Comment ratio and documentation files
- Complexity (40%): Function length and nesting depth
- Organization (30%): Project structure and standards

### Supply Chain & SBOM Scanners

#### Supply Chain Security Scanner
**Focus**: Dependency provenance, build integrity, package security

**Checks**:
- SBOM file presence
- Dependency lock files
- Security documentation

#### SBOM Scanner
**Focus**: Software Bill of Materials compliance

**Checks**:
- SBOM.json, sbom.spdx, bom.xml files
- License compliance documentation
- Third-party attribution

### Government & Defense Scanners

#### ATO Scanner
**Focus**: Authority to Operate readiness

**Checks**:
- Security controls documentation
- Risk assessment documentation
- Monitoring plan
- System Security Plan (SSP)
- Plan of Action & Milestones (POA&M)

#### DEF STAN Scanner
**Focus**: UK defense software standards (DEF STAN 00-970)

**Checks**:
- Safety case documentation
- Hazard analysis
- Defense standards compliance
- Design documentation

#### MIL-STD Scanner
**Focus**: Military software documentation (MIL-STD-498)

**Checks**:
- Software Development Plan (SDP)
- Software Requirements Specification (SRS)
- Software Design Document (SDD)
- Software Test Description/Procedures/Results

#### CMMC Scanner
**Focus**: Cybersecurity Maturity Model Certification

**Checks**:
- NIST 800-171 practices implementation
- Maturity level assessment
- Defense contractor requirements
- SSP and POA&M documentation

### Compliance & Certification Scanners

#### SOC 2 Scanner
**Focus**: SOC 2 Type II trust services

**Checks**:
- Security policy documentation
- Incident response procedures
- Access control documentation
- Audit logs
- Data protection measures
- Business continuity planning

#### ISO 27001 Scanner
**Focus**: ISO 27001 information security management

**Checks**:
- ISMS policy documentation
- Risk register
- Asset inventory
- Security controls implementation
- Information security policy

#### FedRAMP Scanner
**Focus**: Federal Risk and Authorization Management Program

**Checks**:
- NIST 800-53 control implementation
- System Security Plan (SSP)
- Security assessment documentation
- Continuous monitoring evidence

#### CSA STAR Scanner
**Focus**: Cloud Security Alliance STAR certification

**Checks**:
- Cloud security controls
- CSA CCM compliance
- CAIQ (Consensus Assessments Initiative Questionnaire)
- Transparency reporting

### Additional Specialized Scanners

All other scanners (Cloud Compliance, CASE Tools, V&V, Configuration Management, Architecture, Statistical Analysis, Cryptographic Validation, Metadata Management, AI Testing, RegScale, Quality Management, Digital Government, Personnel Security, Global Compliance, Game Warden, Cyber Exchange, HACMS, SafeDocs, V-SPELLs, ARMATURE, EAM, Asset Tracking, Dynamics, Mathematical Analysis) follow the same pattern:

1. Check for framework-specific required files
2. Verify documentation completeness
3. Scan code for domain-specific criteria
4. Calculate compliance score (0-100%)
5. Generate detailed report with strengths, weaknesses, and recommendations

## Report Format

Each scanner generates a detailed report including:

1. **Overall Assessment**
   - Numeric score (0-100)
   - Letter grade (A-F)

2. **Strengths**
   - Positive findings and good practices

3. **Weaknesses**
   - Issues and problems identified

4. **Recommendations**
   - Actionable steps to improve

5. **Summary Statistics**
   - Module-specific metrics

## Example Output

```
======================================================================
Running SECURITY Scanner...
======================================================================

Score: 85.0/100
Grade: B

Report saved to: security_report.txt
```

## Module Structure

```
modules/
├── common/
│   ├── base_scanner.py       # Base scanner class
│   ├── grading.py            # Grading system utilities
│   └── report_generator.py   # Report generation
├── security_scanner/         # Security scanning
├── compliance_scanner/       # Compliance checking
├── vulnerability_scanner/    # Vulnerability detection
├── quality_scanner/          # Quality assessment
├── supply_chain_security_scanner/
├── sbom_scanner/
├── ato_scanner/
├── def_stan_scanner/
├── mil_std_scanner/
├── soc2_scanner/
├── iso27001_scanner/
├── fedramp_scanner/
├── csa_star_scanner/
├── cloud_compliance_scanner/
├── case_tools_scanner/
├── verification_validation_scanner/
├── configuration_management_scanner/
├── architecture_scanner/
├── statistical_analysis_scanner/
├── cryptographic_validation_scanner/
├── metadata_management_scanner/
├── ai_testing_scanner/
├── regscale_scanner/
├── quality_management_scanner/
├── digital_government_scanner/
├── personnel_security_scanner/
├── cmmc_scanner/
├── global_compliance_scanner/
├── game_warden_scanner/
├── cyber_exchange_scanner/
├── hacms_scanner/
├── safedocs_scanner/
├── vspells_scanner/
├── armature_scanner/
├── eam_scanner/
├── asset_tracking_scanner/
├── dynamics_scanner/
└── mathematical_analysis_scanner/
```

## Extending the Modules

Each scanner inherits from `BaseScanner` and implements three key methods:

```python
from common.base_scanner import BaseScanner

class CustomScanner(BaseScanner):
    def scan(self) -> Dict[str, Any]:
        # Perform scanning
        pass
    
    def analyze(self) -> Dict[str, Any]:
        # Analyze results
        pass
    
    def calculate_score(self) -> float:
        # Calculate 0-100 score
        pass
```

## Contributing

Contributions are welcome! Please follow these guidelines:
1. Each scanner should be self-contained in its own directory
2. Maintain consistent grading scales (0-100, A-F)
3. Generate comprehensive reports with actionable recommendations
4. Add documentation for new scanners

## License

See LICENSE file for details.

## References

- **SCAP**: [NIST SCAP](https://csrc.nist.gov/projects/security-content-automation-protocol)
- **STIG**: [DISA STIGs](https://public.cyber.mil/stigs/)
- **ACAS**: [DoD ACAS Program](https://www.disa.mil/acas)
- **BSI IT-Grundschutz**: [BSI Standards](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/it-grundschutz_node.html)

## Support

For issues and questions, please open an issue on the GitHub repository.

# CIV-ARCOS

Civilian Automated Repository Compliance and Operations System - A comprehensive code scanning and compliance assessment platform with 38 specialized modules.

## Overview

CIV-ARCOS provides automated code scanning modules for security, compliance, vulnerability detection, quality assessment, and dozens of government and industry standards. Each module is inspired by industry-standard frameworks and provides detailed reports with actionable recommendations.

## Features

### Core Scanners (4)
- **Security Scanner** (SCAP-inspired) - Detects security vulnerabilities and best practice violations
- **Compliance Scanner** (STIG-inspired) - Checks code compliance with standards and documentation requirements
- **Vulnerability Scanner** (ACAS/Nessus-inspired) - Identifies known vulnerabilities in dependencies
- **Quality Scanner** (BSI IT-Grundschutz-inspired) - Assesses code quality and maintainability

### Supply Chain & SBOM (2)
- **Supply Chain Security Scanner** - Software supply chain security assessment
- **SBOM Scanner** - Software Bill of Materials compliance checking

### Government & Defense (7)
- **ATO Scanner** - Authority to Operate readiness assessment
- **DEF STAN Scanner** - UK defense software standards (DEF STAN 00-970)
- **MIL-STD Scanner** - Military software documentation (MIL-STD-498)
- **CMMC Scanner** - Cybersecurity Maturity Model Certification
- **Cyber Exchange Scanner** - DoD Cyber Exchange compliance
- **HACMS Scanner** - High-Assurance Cyber Military Systems
- **Game Warden Scanner** - DevSecOps platform security compliance

### Compliance & Certifications (5)
- **SOC 2 Scanner** - SOC 2 Type II trust services compliance
- **ISO 27001 Scanner** - ISO 27001 information security standard
- **FedRAMP Scanner** - Federal cloud authorization compliance
- **CSA STAR Scanner** - Cloud Security Alliance certification
- **Global Compliance Scanner** - Multi-jurisdiction regulatory compliance

### Cloud & Infrastructure (1)
- **Cloud Compliance Scanner** - AWS/Azure/GCP compliance verification

### Development & Quality (5)
- **CASE Tools Scanner** - Computer-Aided Software Engineering compliance
- **Verification & Validation Scanner** - V&V processes assessment
- **Configuration Management Scanner** - Configuration management compliance
- **Architecture Scanner** - System design and architecture documentation
- **Mathematical Analysis Scanner** - Mathematical and algorithmic analysis

### Analysis & Testing (4)
- **Statistical Analysis Scanner** - Code metrics and statistical analysis
- **AI Testing Scanner** - AI/ML model testing and characterization
- **SafeDocs Scanner** - Safe document processing security
- **V-SPELLs Scanner** - Legacy software security verification

### Security & Cryptography (2)
- **Cryptographic Validation Scanner** - Cryptographic algorithm validation
- **Personnel Security Scanner** - Personnel security and clearance tracking

### Metadata & Documentation (3)
- **Metadata Management Scanner** - Resource metadata management
- **Quality Management Scanner** - Quality management system compliance
- **Digital Government Scanner** - Government digital services compliance

### Enterprise & Asset Management (5)
- **RegScale Scanner** - Compliance as code automation
- **ARMATURE Scanner** - Accreditation and certification automation
- **EAM Scanner** - Enterprise asset management
- **Asset Tracking Scanner** - Government asset tracking with audit trails
- **Dynamics Scanner** - Microsoft 365 Dynamics for Government

**Total: 38 Specialized Scanning Modules**

Each scanner assigns a score (0-100%) and letter grade (A-F), and generates comprehensive reports detailing:
- Overall assessment and grade
- Strengths and positive findings
- Weaknesses and issues
- Actionable recommendations for improvement

## Quick Start

```bash
# Run all scanners on current directory
python scan.py all .

# Run specific scanner
python scan.py security /path/to/repo

# Run government compliance scanners
python scan.py cmmc /path/to/repo
python scan.py fedramp /path/to/repo

# Generate reports in specific format
python scan.py all . --output reports/ --format markdown
```

## Documentation

For detailed documentation on the scanning modules, see [MODULES_README.md](MODULES_README.md).

## Project Structure

```
CIV-ARCOS/
├── modules/              # 38 Scanning modules
│   ├── common/          # Shared utilities
│   ├── security_scanner/
│   ├── compliance_scanner/
│   ├── vulnerability_scanner/
│   ├── quality_scanner/
│   ├── supply_chain_security_scanner/
│   ├── sbom_scanner/
│   ├── ato_scanner/
│   ├── cmmc_scanner/
│   ├── iso27001_scanner/
│   ├── fedramp_scanner/
│   └── ... (29 more modules)
├── scan.py              # Main CLI interface
├── MODULES_README.md    # Detailed module documentation
└── testing_modules.md   # Module specifications
```

## License

See LICENSE file for details.
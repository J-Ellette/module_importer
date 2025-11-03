"""
CIV-ARCOS Code Scanning Modules

Main CLI interface for running code scanning modules.
"""

import sys
import os
import argparse
from pathlib import Path

# Add modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

from security_scanner import SecurityScanner
from compliance_scanner import ComplianceScanner
from vulnerability_scanner import VulnerabilityScanner
from quality_scanner import QualityScanner
from supply_chain_security_scanner import SupplyChainSecurityScanner
from sbom_scanner import SBOMScanner
from ato_scanner import ATOScanner
from def_stan_scanner import DefStanScanner
from mil_std_scanner import MilStdScanner
from soc2_scanner import SOC2Scanner
from iso27001_scanner import ISO27001Scanner
from fedramp_scanner import FedRAMPScanner
from csa_star_scanner import CSAStarScanner
from cloud_compliance_scanner import CloudComplianceScanner
from case_tools_scanner import CaseToolsScanner
from verification_validation_scanner import VerificationValidationScanner
from configuration_management_scanner import ConfigurationManagementScanner
from architecture_scanner import ArchitectureScanner
from statistical_analysis_scanner import StatisticalAnalysisScanner
from cryptographic_validation_scanner import CryptographicValidationScanner
from metadata_management_scanner import MetadataManagementScanner
from ai_testing_scanner import AITestingScanner
from regscale_scanner import RegScaleScanner
from quality_management_scanner import QualityManagementScanner
from digital_government_scanner import DigitalGovernmentScanner
from personnel_security_scanner import PersonnelSecurityScanner
from cmmc_scanner import CMMCScanner
from global_compliance_scanner import GlobalComplianceScanner
from game_warden_scanner import GameWardenScanner
from cyber_exchange_scanner import CyberExchangeScanner
from hacms_scanner import HACMSScanner
from safedocs_scanner import SafeDocsScanner
from vspells_scanner import VSpellsScanner
from armature_scanner import ArmatureScanner
from eam_scanner import EAMScanner
from asset_tracking_scanner import AssetTrackingScanner
from dynamics_scanner import DynamicsScanner
from mathematical_analysis_scanner import MathematicalAnalysisScanner
from common.report_generator import ReportGenerator


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='CIV-ARCOS Code Scanning Modules',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available Scanners:
  Core Scanners:
    security      - Security vulnerabilities and best practices (SCAP-inspired)
    compliance    - Code compliance and standards adherence (STIG-inspired)
    vulnerability - Dependency vulnerabilities (ACAS/Nessus-inspired)
    quality       - Code quality and maintainability (BSI IT-Grundschutz-inspired)
  
  Supply Chain & SBOM:
    supply_chain  - Software supply chain security assessment
    sbom          - Software Bill of Materials compliance
  
  Government & Defense:
    ato           - Authority to Operate readiness
    def_stan      - UK defense software standards (DEF STAN 00-970)
    mil_std       - Military software documentation (MIL-STD-498)
    cmmc          - Cybersecurity Maturity Model Certification
    cyber_exchange - DoD Cyber Exchange compliance
    hacms         - High-Assurance Cyber Military Systems
    game_warden   - DevSecOps platform security
  
  Compliance & Certifications:
    soc2          - SOC 2 Type II trust services
    iso27001      - ISO 27001 information security
    fedramp       - Federal cloud authorization
    csa_star      - Cloud Security Alliance certification
    global_compliance - Multi-jurisdiction regulatory compliance
  
  Cloud & Infrastructure:
    cloud_compliance - AWS/Azure/GCP compliance
  
  Development & Quality:
    case_tools    - CASE/4GL development tools compliance
    verification_validation - V&V processes
    configuration_management - Configuration management
    architecture  - System design and architecture
    mathematical_analysis - Mathematical and algorithmic analysis
  
  Analysis & Testing:
    statistical_analysis - Code metrics and statistical analysis
    ai_testing    - AI/ML model testing and characterization
    safedocs      - Safe document processing security
    vspells       - Legacy software security verification
  
  Security & Cryptography:
    cryptographic_validation - Cryptographic algorithm validation
    personnel_security - Personnel security and clearance tracking
  
  Metadata & Documentation:
    metadata_management - Resource metadata management
    quality_management - Quality management system
    digital_government - Government digital services
  
  Enterprise & Asset Management:
    regscale      - Compliance as code automation
    armature      - Accreditation and certification automation
    eam           - Enterprise asset management
    asset_tracking - Government asset tracking
    dynamics      - Microsoft 365 Dynamics for Government
  
  all           - Run all scanners

Examples:
  python scan.py security /path/to/repo
  python scan.py all /path/to/repo --output reports/
  python scan.py vulnerability . --format json
  python scan.py cmmc /path/to/repo --format markdown
        """
    )
    
    parser.add_argument(
        'scanner',
        choices=[
            'security', 'compliance', 'vulnerability', 'quality',
            'supply_chain', 'sbom', 'ato', 'def_stan', 'mil_std',
            'soc2', 'iso27001', 'fedramp', 'csa_star', 'cloud_compliance',
            'case_tools', 'verification_validation', 'configuration_management',
            'architecture', 'statistical_analysis', 'cryptographic_validation',
            'metadata_management', 'ai_testing', 'regscale', 'quality_management',
            'digital_government', 'personnel_security', 'cmmc', 'global_compliance',
            'game_warden', 'cyber_exchange', 'hacms', 'safedocs', 'vspells',
            'armature', 'eam', 'asset_tracking', 'dynamics', 'mathematical_analysis',
            'all'
        ],
        help='Scanner to run'
    )
    
    parser.add_argument(
        'path',
        help='Path to repository or directory to scan'
    )
    
    parser.add_argument(
        '--output',
        '-o',
        help='Output directory for reports (default: current directory)',
        default='.'
    )
    
    parser.add_argument(
        '--format',
        '-f',
        choices=['text', 'markdown', 'json'],
        default='text',
        help='Report format (default: text)'
    )
    
    args = parser.parse_args()
    
    # Validate path
    target_path = Path(args.path).resolve()
    if not target_path.exists():
        print(f"Error: Path does not exist: {target_path}")
        sys.exit(1)
    
    # Create output directory if needed
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Determine which scanners to run
    scanners = {
        'security': SecurityScanner,
        'compliance': ComplianceScanner,
        'vulnerability': VulnerabilityScanner,
        'quality': QualityScanner,
        'supply_chain': SupplyChainSecurityScanner,
        'sbom': SBOMScanner,
        'ato': ATOScanner,
        'def_stan': DefStanScanner,
        'mil_std': MilStdScanner,
        'soc2': SOC2Scanner,
        'iso27001': ISO27001Scanner,
        'fedramp': FedRAMPScanner,
        'csa_star': CSAStarScanner,
        'cloud_compliance': CloudComplianceScanner,
        'case_tools': CaseToolsScanner,
        'verification_validation': VerificationValidationScanner,
        'configuration_management': ConfigurationManagementScanner,
        'architecture': ArchitectureScanner,
        'statistical_analysis': StatisticalAnalysisScanner,
        'cryptographic_validation': CryptographicValidationScanner,
        'metadata_management': MetadataManagementScanner,
        'ai_testing': AITestingScanner,
        'regscale': RegScaleScanner,
        'quality_management': QualityManagementScanner,
        'digital_government': DigitalGovernmentScanner,
        'personnel_security': PersonnelSecurityScanner,
        'cmmc': CMMCScanner,
        'global_compliance': GlobalComplianceScanner,
        'game_warden': GameWardenScanner,
        'cyber_exchange': CyberExchangeScanner,
        'hacms': HACMSScanner,
        'safedocs': SafeDocsScanner,
        'vspells': VSpellsScanner,
        'armature': ArmatureScanner,
        'eam': EAMScanner,
        'asset_tracking': AssetTrackingScanner,
        'dynamics': DynamicsScanner,
        'mathematical_analysis': MathematicalAnalysisScanner,
    }
    
    if args.scanner == 'all':
        scanners_to_run = scanners
    else:
        scanners_to_run = {args.scanner: scanners[args.scanner]}
    
    # Run scanners
    results = {}
    for name, scanner_class in scanners_to_run.items():
        print(f"\n{'='*70}")
        print(f"Running {name.upper()} Scanner...")
        print(f"{'='*70}")
        
        try:
            scanner = scanner_class(str(target_path))
            result = scanner.run()
            results[name] = result
            
            # Print summary
            print(f"\nScore: {result['score']:.1f}/100")
            print(f"Grade: {result['grade']}")
            
            # Save report
            ext = 'txt' if args.format == 'text' else args.format
            output_file = output_dir / f"{name}_report.{ext}"
            ReportGenerator.save_report(result, str(output_file), args.format)
            print(f"\nReport saved to: {output_file}")
            
        except Exception as e:
            print(f"Error running {name} scanner: {e}")
            continue
    
    # Generate combined report if running all scanners
    if args.scanner == 'all' and results:
        print(f"\n{'='*70}")
        print("COMBINED RESULTS")
        print(f"{'='*70}")
        
        total_score = sum(r['score'] for r in results.values()) / len(results)
        
        print(f"\nOverall Average Score: {total_score:.1f}/100")
        print(f"\nIndividual Scores:")
        for name, result in results.items():
            print(f"  {name.capitalize():15} {result['score']:5.1f}/100 (Grade: {result['grade']})")
        
        # Save combined summary
        combined_file = output_dir / f"combined_summary.txt"
        with open(combined_file, 'w') as f:
            f.write("CIV-ARCOS Combined Scan Report\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Target: {target_path}\n")
            f.write(f"Overall Average Score: {total_score:.1f}/100\n\n")
            f.write("Individual Scores:\n")
            for name, result in results.items():
                f.write(f"  {name.capitalize():15} {result['score']:5.1f}/100 (Grade: {result['grade']})\n")
        
        print(f"\nCombined summary saved to: {combined_file}")


if __name__ == '__main__':
    main()

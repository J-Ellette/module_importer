"""
Test that all 38 scanners can be instantiated and run successfully.
"""

import unittest
import sys
import os
from pathlib import Path
import tempfile
import shutil

# Add modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))

# Import all scanners
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


class TestAllScanners(unittest.TestCase):
    """Test that all scanners can be instantiated and run."""
    
    def setUp(self):
        """Set up test directory."""
        self.test_dir = tempfile.mkdtemp()
        # Create a simple test file
        (Path(self.test_dir) / 'test.py').write_text("""
def hello():
    print("Hello, World!")
""")
    
    def tearDown(self):
        """Clean up test directory."""
        shutil.rmtree(self.test_dir)
    
    def _test_scanner(self, scanner_class, scanner_name):
        """Helper method to test a scanner."""
        try:
            scanner = scanner_class(self.test_dir)
            results = scanner.run()
            
            # Verify required fields in results
            self.assertIn('score', results, f"{scanner_name} missing 'score' in results")
            self.assertIn('grade', results, f"{scanner_name} missing 'grade' in results")
            self.assertIn('analysis', results, f"{scanner_name} missing 'analysis' in results")
            
            # Verify score is in valid range
            self.assertGreaterEqual(results['score'], 0.0, f"{scanner_name} score below 0")
            self.assertLessEqual(results['score'], 100.0, f"{scanner_name} score above 100")
            
            # Verify grade is valid
            self.assertIn(results['grade'], ['A', 'B', 'C', 'D', 'F'], 
                         f"{scanner_name} invalid grade: {results['grade']}")
            
            return True
        except Exception as e:
            self.fail(f"{scanner_name} failed: {str(e)}")
    
    def test_core_scanners(self):
        """Test core scanners."""
        self._test_scanner(SecurityScanner, "SecurityScanner")
        self._test_scanner(ComplianceScanner, "ComplianceScanner")
        self._test_scanner(VulnerabilityScanner, "VulnerabilityScanner")
        self._test_scanner(QualityScanner, "QualityScanner")
    
    def test_supply_chain_scanners(self):
        """Test supply chain scanners."""
        self._test_scanner(SupplyChainSecurityScanner, "SupplyChainSecurityScanner")
        self._test_scanner(SBOMScanner, "SBOMScanner")
    
    def test_government_defense_scanners(self):
        """Test government and defense scanners."""
        self._test_scanner(ATOScanner, "ATOScanner")
        self._test_scanner(DefStanScanner, "DefStanScanner")
        self._test_scanner(MilStdScanner, "MilStdScanner")
        self._test_scanner(CMMCScanner, "CMMCScanner")
        self._test_scanner(CyberExchangeScanner, "CyberExchangeScanner")
        self._test_scanner(HACMSScanner, "HACMSScanner")
        self._test_scanner(GameWardenScanner, "GameWardenScanner")
    
    def test_compliance_certification_scanners(self):
        """Test compliance and certification scanners."""
        self._test_scanner(SOC2Scanner, "SOC2Scanner")
        self._test_scanner(ISO27001Scanner, "ISO27001Scanner")
        self._test_scanner(FedRAMPScanner, "FedRAMPScanner")
        self._test_scanner(CSAStarScanner, "CSAStarScanner")
        self._test_scanner(GlobalComplianceScanner, "GlobalComplianceScanner")
    
    def test_cloud_infrastructure_scanners(self):
        """Test cloud and infrastructure scanners."""
        self._test_scanner(CloudComplianceScanner, "CloudComplianceScanner")
    
    def test_development_quality_scanners(self):
        """Test development and quality scanners."""
        self._test_scanner(CaseToolsScanner, "CaseToolsScanner")
        self._test_scanner(VerificationValidationScanner, "VerificationValidationScanner")
        self._test_scanner(ConfigurationManagementScanner, "ConfigurationManagementScanner")
        self._test_scanner(ArchitectureScanner, "ArchitectureScanner")
        self._test_scanner(MathematicalAnalysisScanner, "MathematicalAnalysisScanner")
    
    def test_analysis_testing_scanners(self):
        """Test analysis and testing scanners."""
        self._test_scanner(StatisticalAnalysisScanner, "StatisticalAnalysisScanner")
        self._test_scanner(AITestingScanner, "AITestingScanner")
        self._test_scanner(SafeDocsScanner, "SafeDocsScanner")
        self._test_scanner(VSpellsScanner, "VSpellsScanner")
    
    def test_security_cryptography_scanners(self):
        """Test security and cryptography scanners."""
        self._test_scanner(CryptographicValidationScanner, "CryptographicValidationScanner")
        self._test_scanner(PersonnelSecurityScanner, "PersonnelSecurityScanner")
    
    def test_metadata_documentation_scanners(self):
        """Test metadata and documentation scanners."""
        self._test_scanner(MetadataManagementScanner, "MetadataManagementScanner")
        self._test_scanner(QualityManagementScanner, "QualityManagementScanner")
        self._test_scanner(DigitalGovernmentScanner, "DigitalGovernmentScanner")
    
    def test_enterprise_asset_management_scanners(self):
        """Test enterprise and asset management scanners."""
        self._test_scanner(RegScaleScanner, "RegScaleScanner")
        self._test_scanner(ArmatureScanner, "ArmatureScanner")
        self._test_scanner(EAMScanner, "EAMScanner")
        self._test_scanner(AssetTrackingScanner, "AssetTrackingScanner")
        self._test_scanner(DynamicsScanner, "DynamicsScanner")
    
    def test_all_scanners_count(self):
        """Verify we have all 38 scanners."""
        all_scanners = [
            SecurityScanner, ComplianceScanner, VulnerabilityScanner, QualityScanner,
            SupplyChainSecurityScanner, SBOMScanner, ATOScanner, DefStanScanner,
            MilStdScanner, SOC2Scanner, ISO27001Scanner, FedRAMPScanner,
            CSAStarScanner, CloudComplianceScanner, CaseToolsScanner,
            VerificationValidationScanner, ConfigurationManagementScanner,
            ArchitectureScanner, StatisticalAnalysisScanner, CryptographicValidationScanner,
            MetadataManagementScanner, AITestingScanner, RegScaleScanner,
            QualityManagementScanner, DigitalGovernmentScanner, PersonnelSecurityScanner,
            CMMCScanner, GlobalComplianceScanner, GameWardenScanner, CyberExchangeScanner,
            HACMSScanner, SafeDocsScanner, VSpellsScanner, ArmatureScanner,
            EAMScanner, AssetTrackingScanner, DynamicsScanner, MathematicalAnalysisScanner
        ]
        
        self.assertEqual(len(all_scanners), 38, 
                        f"Expected 38 scanners, found {len(all_scanners)}")


if __name__ == '__main__':
    unittest.main()

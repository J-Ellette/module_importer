"""
Tests for the CIV-ARCOS scanning modules.
"""

import unittest
import sys
import os
from pathlib import Path
import tempfile
import shutil

# Add modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))

from security_scanner import SecurityScanner
from compliance_scanner import ComplianceScanner
from vulnerability_scanner import VulnerabilityScanner
from quality_scanner import QualityScanner
from common.grading import GradingSystem


class TestGradingSystem(unittest.TestCase):
    """Test the grading system utilities."""
    
    def test_get_grade(self):
        """Test grade assignment."""
        self.assertEqual(GradingSystem.get_grade(95), 'A')
        self.assertEqual(GradingSystem.get_grade(85), 'B')
        self.assertEqual(GradingSystem.get_grade(75), 'C')
        self.assertEqual(GradingSystem.get_grade(65), 'D')
        self.assertEqual(GradingSystem.get_grade(50), 'F')
    
    def test_weighted_score(self):
        """Test weighted score calculation."""
        components = {
            'component1': (80, 1.0),
            'component2': (60, 1.0),
        }
        score = GradingSystem.calculate_weighted_score(components)
        self.assertEqual(score, 70.0)
    
    def test_normalize_score(self):
        """Test score normalization."""
        score = GradingSystem.normalize_score(5, 0, 10)
        self.assertEqual(score, 50.0)


class TestSecurityScanner(unittest.TestCase):
    """Test the Security Scanner."""
    
    def setUp(self):
        """Set up test directory."""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = Path(self.test_dir) / 'test.py'
    
    def tearDown(self):
        """Clean up test directory."""
        shutil.rmtree(self.test_dir)
    
    def test_clean_code(self):
        """Test scanning clean code."""
        code = """
def hello_world():
    print("Hello, World!")
"""
        self.test_file.write_text(code)
        
        scanner = SecurityScanner(self.test_dir)
        results = scanner.run()
        
        self.assertIsNotNone(results['score'])
        self.assertGreaterEqual(results['score'], 80)
        self.assertIn('grade', results)
    
    def test_hardcoded_password(self):
        """Test detection of hardcoded passwords."""
        code = """
password = "secret123"
db_connect(password=password)
"""
        self.test_file.write_text(code)
        
        scanner = SecurityScanner(self.test_dir)
        results = scanner.run()
        
        self.assertLess(results['score'], 100)
        self.assertGreater(results['analysis']['summary']['total_issues'], 0)
    
    def test_command_injection(self):
        """Test detection of command injection."""
        code = """
import os
os.system("rm -rf " + user_input)
"""
        self.test_file.write_text(code)
        
        scanner = SecurityScanner(self.test_dir)
        results = scanner.run()
        
        # Should detect command injection pattern
        self.assertGreater(results['analysis']['summary']['total_issues'], 0)


class TestComplianceScanner(unittest.TestCase):
    """Test the Compliance Scanner."""
    
    def setUp(self):
        """Set up test directory."""
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test directory."""
        shutil.rmtree(self.test_dir)
    
    def test_missing_documentation(self):
        """Test detection of missing documentation."""
        scanner = ComplianceScanner(self.test_dir)
        results = scanner.run()
        
        self.assertIsNotNone(results['score'])
        self.assertLess(results['score'], 50)  # Should fail without required files
    
    def test_with_readme(self):
        """Test with README present."""
        (Path(self.test_dir) / 'README.md').write_text("# Test Project")
        
        scanner = ComplianceScanner(self.test_dir)
        results = scanner.run()
        
        self.assertGreater(results['score'], 0)
    
    def test_with_license(self):
        """Test with LICENSE present."""
        (Path(self.test_dir) / 'LICENSE').write_text("MIT License")
        (Path(self.test_dir) / 'README.md').write_text("# Test")
        
        scanner = ComplianceScanner(self.test_dir)
        results = scanner.run()
        
        # Should have better score with both files
        self.assertGreater(results['score'], 20)


class TestVulnerabilityScanner(unittest.TestCase):
    """Test the Vulnerability Scanner."""
    
    def setUp(self):
        """Set up test directory."""
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test directory."""
        shutil.rmtree(self.test_dir)
    
    def test_no_dependencies(self):
        """Test scanning with no dependencies."""
        scanner = VulnerabilityScanner(self.test_dir)
        results = scanner.run()
        
        self.assertIsNotNone(results['score'])
        self.assertEqual(results['score'], 70.0)  # Neutral score
    
    def test_with_requirements(self):
        """Test with requirements.txt file."""
        requirements = "requests==2.25.0\nflask==1.1.0\n"
        (Path(self.test_dir) / 'requirements.txt').write_text(requirements)
        
        scanner = VulnerabilityScanner(self.test_dir)
        results = scanner.run()
        
        self.assertGreater(results['analysis']['summary']['dependencies_scanned'], 0)


class TestQualityScanner(unittest.TestCase):
    """Test the Quality Scanner."""
    
    def setUp(self):
        """Set up test directory."""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = Path(self.test_dir) / 'test.py'
    
    def tearDown(self):
        """Clean up test directory."""
        shutil.rmtree(self.test_dir)
    
    def test_simple_code(self):
        """Test scanning simple code."""
        code = """
def hello():
    \"\"\"Say hello.\"\"\"
    print("Hello")

def goodbye():
    \"\"\"Say goodbye.\"\"\"
    print("Goodbye")
"""
        self.test_file.write_text(code)
        
        scanner = QualityScanner(self.test_dir)
        results = scanner.run()
        
        self.assertIsNotNone(results['score'])
        self.assertGreater(results['analysis']['summary']['code_files'], 0)
    
    def test_with_documentation(self):
        """Test with documentation files."""
        code = """# Simple code
def test():
    pass
"""
        self.test_file.write_text(code)
        (Path(self.test_dir) / 'README.md').write_text("# Test")
        
        scanner = QualityScanner(self.test_dir)
        results = scanner.run()
        
        self.assertGreater(results['analysis']['summary']['documentation_files'], 0)


if __name__ == '__main__':
    unittest.main()

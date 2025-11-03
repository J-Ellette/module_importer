"""
Advanced scanner module - main entry point.

This is a multi-file module that demonstrates the module container system.
"""

import sys
import os
from typing import Dict, Any, List

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from module_base import ModuleBase
from .scanner_engine import ScannerEngine
from .report_generator import ReportGenerator


class AdvancedScannerModule(ModuleBase):
    """
    Advanced scanner module with multiple components.
    
    Demonstrates a multi-file module using the container system.
    """
    
    def get_name(self) -> str:
        """Return the module name."""
        return "advanced_scanner"
    
    def get_version(self) -> str:
        """Return the module version."""
        return "2.0.0"
    
    def get_description(self) -> str:
        """Return the module description."""
        return "Advanced code scanner with multiple analysis engines and report generation"
    
    def initialize(self) -> bool:
        """Initialize the scanner module."""
        try:
            # Initialize scanner engine
            self.scanner = ScannerEngine(self.config)
            
            # Initialize report generator
            self.reporter = ReportGenerator(self.config)
            
            return True
        except Exception as e:
            print(f"Error initializing advanced scanner: {e}")
            return False
    
    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the advanced scanning.
        
        Args:
            **kwargs: Can include:
                - path: Path to scan
                - scan_types: List of scan types to run
                - output_format: Report output format
        
        Returns:
            Dictionary with scan results and report
        """
        path = kwargs.get('path', '.')
        scan_types = kwargs.get('scan_types', ['security', 'quality'])
        output_format = kwargs.get('output_format', 'json')
        
        # Run scans
        scan_results = self.scanner.scan(path, scan_types)
        
        # Generate report
        report = self.reporter.generate_report(scan_results, output_format)
        
        return {
            'success': True,
            'scan_results': scan_results,
            'report': report,
            'summary': {
                'scans_run': len(scan_types),
                'total_issues': scan_results.get('total_issues', 0),
                'critical_issues': scan_results.get('critical_issues', 0)
            }
        }
    
    def get_dependencies(self) -> List[str]:
        """Return list of module dependencies."""
        return []

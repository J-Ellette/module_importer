"""
Global Compliance Scanner Module - Adapted for ModuleBase interface.
"""

import sys
import os
from typing import Dict, Any, List

# Add parent directory to path for module_base import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from module_base import ModuleBase
from .scanner import GlobalComplianceScanner
from common.report_generator import ReportGenerator


class GlobalComplianceScannerModule(ModuleBase):
    """
    ModuleBase wrapper for GlobalComplianceScanner.
    """
    
    def get_name(self) -> str:
        """Return the module name."""
        return "global_compliance_scanner"
    
    def get_version(self) -> str:
        """Return the module version."""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Return the module description."""
        return "Global Compliance Scanner - Code scanning and analysis module"
    
    def initialize(self) -> bool:
        """Initialize the scanner module."""
        self.scanner = None
        return True
    
    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the scanner.
        
        Args:
            path: Path to scan (required)
            output_format: Report format ('json', 'text', 'markdown')
            **kwargs: Additional scanner-specific arguments
            
        Returns:
            Scanner results dictionary
        """
        target_path = kwargs.get('path', '.')
        output_format = kwargs.get('output_format', 'json')
        
        try:
            # Create scanner instance
            self.scanner = GlobalComplianceScanner(target_path)
            
            # Run the scanning pipeline
            results = self.scanner.run()
            
            # Generate report
            if output_format == 'json':
                report = ReportGenerator.generate_json_report(results)
            elif output_format == 'text':
                report = ReportGenerator.generate_text_report(results)
            elif output_format == 'markdown':
                report = ReportGenerator.generate_markdown_report(results)
            else:
                report = ReportGenerator.generate_json_report(results)
            
            return {
                'success': True,
                'module': self.get_name(),
                'scanner': results.get('scanner'),
                'target_path': str(target_path),
                'timestamp': results.get('timestamp'),
                'score': results.get('score', 0.0),
                'grade': results.get('grade', 'N/A'),
                'analysis': results.get('analysis', {}),
                'scan_results': results.get('raw_results', {}),
                'report': report
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'module': self.get_name()
            }
    
    def shutdown(self) -> None:
        """Clean up scanner resources."""
        self.scanner = None


# Export the module class
__all__ = ['GlobalComplianceScannerModule']

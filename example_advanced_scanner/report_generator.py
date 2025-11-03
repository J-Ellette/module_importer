"""
Report generator for the advanced scanner module.

Generates reports in various formats from scan results.
"""

import json
from typing import Dict, Any


class ReportGenerator:
    """
    Report generator that creates reports from scan results.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the report generator.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.format_handlers = {
            'json': self._generate_json_report,
            'text': self._generate_text_report,
            'summary': self._generate_summary_report
        }
    
    def generate_report(self, scan_results: Dict[str, Any], format: str = 'json') -> str:
        """
        Generate a report from scan results.
        
        Args:
            scan_results: Results from scanner
            format: Output format (json, text, summary)
            
        Returns:
            Formatted report string
        """
        if format in self.format_handlers:
            return self.format_handlers[format](scan_results)
        else:
            return self._generate_json_report(scan_results)
    
    def _generate_json_report(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate JSON format report.
        
        Args:
            scan_results: Results from scanner
            
        Returns:
            JSON formatted report
        """
        return json.dumps(scan_results, indent=2)
    
    def _generate_text_report(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate plain text report.
        
        Args:
            scan_results: Results from scanner
            
        Returns:
            Plain text formatted report
        """
        lines = []
        lines.append("=" * 60)
        lines.append("Advanced Scanner Report")
        lines.append("=" * 60)
        lines.append(f"Scanned path: {scan_results.get('path', 'N/A')}")
        lines.append(f"Total issues: {scan_results.get('total_issues', 0)}")
        lines.append(f"Critical issues: {scan_results.get('critical_issues', 0)}")
        lines.append("")
        
        for scan_type, scan_data in scan_results.get('scans', {}).items():
            lines.append(f"Scan Type: {scan_type.upper()}")
            lines.append(f"Issues found: {scan_data.get('issue_count', 0)}")
            
            issues = scan_data.get('issues', [])
            if issues:
                lines.append("\nIssues:")
                for issue in issues[:10]:  # Show first 10
                    lines.append(f"  - {issue.get('file', 'N/A')}:{issue.get('line', 0)}")
                    lines.append(f"    Type: {issue.get('type', 'unknown')}, Severity: {issue.get('severity', 'unknown')}")
                
                if len(issues) > 10:
                    lines.append(f"  ... and {len(issues) - 10} more issues")
            
            lines.append("")
        
        return "\n".join(lines)
    
    def _generate_summary_report(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate summary report.
        
        Args:
            scan_results: Results from scanner
            
        Returns:
            Summary formatted report
        """
        lines = []
        lines.append("Scan Summary")
        lines.append("-" * 40)
        lines.append(f"Path: {scan_results.get('path', 'N/A')}")
        lines.append(f"Total issues: {scan_results.get('total_issues', 0)}")
        lines.append(f"Critical: {scan_results.get('critical_issues', 0)}")
        
        scans = scan_results.get('scans', {})
        if scans:
            lines.append(f"Scans run: {', '.join(scans.keys())}")
        
        return "\n".join(lines)

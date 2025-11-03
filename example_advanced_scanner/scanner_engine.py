"""
Scanner engine for the advanced scanner module.

Handles the actual scanning logic.
"""

import os
import re
from typing import Dict, Any, List


class ScannerEngine:
    """
    Scanner engine that performs various types of code analysis.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the scanner engine.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.scan_handlers = {
            'security': self._security_scan,
            'quality': self._quality_scan,
            'complexity': self._complexity_scan
        }
    
    def scan(self, path: str, scan_types: List[str]) -> Dict[str, Any]:
        """
        Perform scanning on the given path.
        
        Args:
            path: Path to scan
            scan_types: Types of scans to perform
            
        Returns:
            Dictionary with scan results
        """
        results = {
            'path': path,
            'scans': {},
            'total_issues': 0,
            'critical_issues': 0
        }
        
        for scan_type in scan_types:
            if scan_type in self.scan_handlers:
                scan_result = self.scan_handlers[scan_type](path)
                results['scans'][scan_type] = scan_result
                results['total_issues'] += scan_result.get('issue_count', 0)
                results['critical_issues'] += scan_result.get('critical_count', 0)
        
        return results
    
    def _security_scan(self, path: str) -> Dict[str, Any]:
        """
        Perform security scanning.
        
        Args:
            path: Path to scan
            
        Returns:
            Security scan results
        """
        issues = []
        
        # Simple security patterns
        patterns = {
            'hardcoded_secret': re.compile(r'(password|secret|api_key)\s*=\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
            'sql_injection': re.compile(r'execute\s*\([^)]*%[sdf]', re.IGNORECASE),
        }
        
        if os.path.isfile(path):
            files_to_scan = [path]
        else:
            files_to_scan = self._get_python_files(path)
        
        for file_path in files_to_scan:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern_name, pattern in patterns.items():
                            if pattern.search(line):
                                issues.append({
                                    'file': file_path,
                                    'line': line_num,
                                    'type': pattern_name,
                                    'severity': 'critical'
                                })
            except Exception:
                pass
        
        return {
            'scan_type': 'security',
            'issues': issues,
            'issue_count': len(issues),
            'critical_count': len([i for i in issues if i['severity'] == 'critical'])
        }
    
    def _quality_scan(self, path: str) -> Dict[str, Any]:
        """
        Perform code quality scanning.
        
        Args:
            path: Path to scan
            
        Returns:
            Quality scan results
        """
        issues = []
        
        # Simple quality patterns
        patterns = {
            'long_line': lambda line: len(line) > 120,
            'todo_comment': lambda line: 'TODO' in line.upper() or 'FIXME' in line.upper(),
        }
        
        if os.path.isfile(path):
            files_to_scan = [path]
        else:
            files_to_scan = self._get_python_files(path)
        
        for file_path in files_to_scan:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        if patterns['long_line'](line):
                            issues.append({
                                'file': file_path,
                                'line': line_num,
                                'type': 'long_line',
                                'severity': 'low'
                            })
                        if patterns['todo_comment'](line):
                            issues.append({
                                'file': file_path,
                                'line': line_num,
                                'type': 'todo_comment',
                                'severity': 'info'
                            })
            except Exception:
                pass
        
        return {
            'scan_type': 'quality',
            'issues': issues,
            'issue_count': len(issues),
            'critical_count': 0
        }
    
    def _complexity_scan(self, path: str) -> Dict[str, Any]:
        """
        Perform complexity analysis.
        
        Args:
            path: Path to scan
            
        Returns:
            Complexity scan results
        """
        # Simplified complexity analysis
        return {
            'scan_type': 'complexity',
            'issues': [],
            'issue_count': 0,
            'critical_count': 0,
            'message': 'Complexity analysis not yet implemented'
        }
    
    def _get_python_files(self, path: str) -> List[str]:
        """
        Get list of Python files in path.
        
        Args:
            path: Directory path
            
        Returns:
            List of Python file paths
        """
        python_files = []
        
        try:
            for root, dirs, files in os.walk(path):
                # Skip hidden and common ignored directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'venv']]
                
                for file in files:
                    if file.endswith('.py'):
                        python_files.append(os.path.join(root, file))
        except Exception:
            pass
        
        return python_files

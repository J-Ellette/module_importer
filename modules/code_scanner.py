"""
Code scanning module for analyzing repository code.

This module demonstrates a code scanning implementation that can be used
to scan repositories for various issues, patterns, or security concerns.
"""

import os
import re
from typing import Dict, Any, List
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from module_base import ModuleBase


class CodeScanningModule(ModuleBase):
    """
    Code scanning module for analyzing repository code.
    
    This module can scan code files for:
    - Security issues (hardcoded secrets, SQL injection patterns)
    - Code quality issues
    - Common bugs and anti-patterns
    """
    
    def get_name(self) -> str:
        """Return the module name."""
        return "code_scanner"
    
    def get_version(self) -> str:
        """Return the module version."""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Return the module description."""
        return "Scans repository code for security issues, bugs, and quality concerns"
    
    def initialize(self) -> bool:
        """Initialize the code scanner module."""
        # Initialize scanning patterns
        self.security_patterns = {
            'hardcoded_password': re.compile(r'password\s*=\s*["\'][^"\']+["\']', re.IGNORECASE),
            'hardcoded_api_key': re.compile(r'api[_-]?key\s*=\s*["\'][^"\']+["\']', re.IGNORECASE),
            'sql_injection': re.compile(r'execute\s*\(\s*["\'].*%s.*["\']', re.IGNORECASE),
            'debug_mode': re.compile(r'DEBUG\s*=\s*True', re.IGNORECASE),
        }
        
        self.file_extensions = self.config.get('file_extensions', [
            '.py', '.js', '.ts', '.java', '.cpp', '.c', '.go', '.rb', '.php'
        ])
        
        return True
    
    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the code scanning.
        
        Args:
            **kwargs: Can include:
                - path: Path to scan (file or directory)
                - patterns: Custom patterns to scan for
                - recursive: Whether to scan recursively (default: True)
        
        Returns:
            Dictionary with scan results
        """
        path = kwargs.get('path', '.')
        recursive = kwargs.get('recursive', True)
        custom_patterns = kwargs.get('patterns', {})
        
        # Merge custom patterns with default patterns
        patterns = {**self.security_patterns, **custom_patterns}
        
        results = {
            'scanned_files': [],
            'issues_found': [],
            'summary': {
                'total_files': 0,
                'files_with_issues': 0,
                'total_issues': 0
            }
        }
        
        # Scan the path
        if os.path.isfile(path):
            self._scan_file(path, patterns, results)
        elif os.path.isdir(path):
            self._scan_directory(path, patterns, results, recursive)
        else:
            return {
                'error': f"Path not found: {path}",
                'success': False
            }
        
        # Update summary
        results['summary']['total_files'] = len(results['scanned_files'])
        results['summary']['files_with_issues'] = len(set(
            issue['file'] for issue in results['issues_found']
        ))
        results['summary']['total_issues'] = len(results['issues_found'])
        results['success'] = True
        
        return results
    
    def _scan_file(self, file_path: str, patterns: Dict[str, re.Pattern], results: Dict[str, Any]) -> None:
        """
        Scan a single file for issues.
        
        Args:
            file_path: Path to the file to scan
            patterns: Dictionary of pattern names to regex patterns
            results: Results dictionary to update
        """
        # Check if file should be scanned
        if not any(file_path.endswith(ext) for ext in self.file_extensions):
            return
        
        results['scanned_files'].append(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                for pattern_name, pattern in patterns.items():
                    if pattern.search(line):
                        results['issues_found'].append({
                            'file': file_path,
                            'line': line_num,
                            'issue_type': pattern_name,
                            'content': line.strip(),
                            'severity': self._get_severity(pattern_name)
                        })
        except Exception as e:
            results['issues_found'].append({
                'file': file_path,
                'line': 0,
                'issue_type': 'scan_error',
                'content': str(e),
                'severity': 'info'
            })
    
    def _scan_directory(self, dir_path: str, patterns: Dict[str, re.Pattern], 
                       results: Dict[str, Any], recursive: bool) -> None:
        """
        Scan a directory for issues.
        
        Args:
            dir_path: Path to the directory to scan
            patterns: Dictionary of pattern names to regex patterns
            results: Results dictionary to update
            recursive: Whether to scan subdirectories
        """
        try:
            for item in os.listdir(dir_path):
                item_path = os.path.join(dir_path, item)
                
                # Skip hidden files and common directories to ignore
                if item.startswith('.') or item in ['node_modules', 'venv', '__pycache__', 'dist', 'build']:
                    continue
                
                if os.path.isfile(item_path):
                    self._scan_file(item_path, patterns, results)
                elif os.path.isdir(item_path) and recursive:
                    self._scan_directory(item_path, patterns, results, recursive)
        except Exception as e:
            results['issues_found'].append({
                'file': dir_path,
                'line': 0,
                'issue_type': 'scan_error',
                'content': f"Error scanning directory: {e}",
                'severity': 'info'
            })
    
    def _get_severity(self, issue_type: str) -> str:
        """
        Get severity level for an issue type.
        
        Args:
            issue_type: Type of issue
            
        Returns:
            Severity level (critical, high, medium, low, info)
        """
        severity_map = {
            'hardcoded_password': 'critical',
            'hardcoded_api_key': 'critical',
            'sql_injection': 'high',
            'debug_mode': 'medium',
        }
        return severity_map.get(issue_type, 'low')
    
    def get_dependencies(self) -> List[str]:
        """Return list of module dependencies."""
        return []

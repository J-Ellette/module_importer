"""
Security Scanner implementation for detecting security vulnerabilities in code.
"""

import re
import os
from pathlib import Path
from typing import Dict, List, Any, Set
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.base_scanner import BaseScanner
from common.grading import GradingSystem


class SecurityScanner(BaseScanner):
    """
    Security-focused code scanner based on SCAP principles.
    
    Scans for common security issues including:
- Hard-coded secrets and credentials
- Weak cryptographic practices
- Injection vulnerabilities
- Insecure file operations
    """
    
    # Security patterns to detect
    SECURITY_PATTERNS = {
        'hardcoded_password': [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'passwd\s*=\s*["\'][^"\']+["\']',
            r'pwd\s*=\s*["\'][^"\']+["\']',
        ],
        'api_key': [
            r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
            r'apikey\s*=\s*["\'][^"\']+["\']',
            r'access[_-]?key\s*=\s*["\'][^"\']+["\']',
        ],
        'secret_token': [
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
            r'auth[_-]?token\s*=\s*["\'][^"\']+["\']',
        ],
        'sql_injection': [
            r'execute\s*\(\s*["\'].*%s.*["\']',
            r'\.query\s*\(\s*["\'].*\+.*["\']',
            r'SELECT.*\+.*FROM',
        ],
        'command_injection': [
            r'os\.system\s*\(',
            r'subprocess\.call\s*\(',
            r'eval\s*\(',
            r'exec\s*\(',
        ],
        'weak_crypto': [
            r'md5\s*\(',
            r'sha1\s*\(',
            r'DES\s*\(',
        ],
        'insecure_random': [
            r'random\.random\s*\(',
            r'Math\.random\s*\(',
        ],
        'insecure_file_operations': [
            r'pickle\.load',  # Unsafe deserialization
            r'yaml\.load\s*\([^)]*\)',  # Should use safe_load
            r'eval\s*\(',  # Already in command_injection but also insecure file op
        ],
    }
    
    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        '.py', '.js', '.ts', '.java', '.rb', '.php', '.go', '.cs',
        '.cpp', '.c', '.h', '.sh', '.bash', '.yml', '.yaml', '.json', '.xml'
    }
    
    def __init__(self, target_path: str):
        """Initialize the security scanner."""
        super().__init__(target_path)
        self.files_scanned = 0
        self.issues_found = {}
    
    def scan(self) -> Dict[str, Any]:
        """
        Scan the target directory for security issues.
        
        Returns:
            Dictionary containing scan results
        """
        results = {
            'files_scanned': 0,
            'issues_by_type': {},
            'issues_by_file': {},
            'total_issues': 0
        }
        
        # Initialize issue counters
        for issue_type in self.SECURITY_PATTERNS:
            results['issues_by_type'][issue_type] = 0
        
        # Scan all files
        for file_path in self._get_scannable_files():
            file_issues = self._scan_file(file_path)
            if file_issues:
                results['issues_by_file'][str(file_path)] = file_issues
                for issue_type, count in file_issues.items():
                    results['issues_by_type'][issue_type] += count
                    results['total_issues'] += count
            
            results['files_scanned'] += 1
        
        self.files_scanned = results['files_scanned']
        self.issues_found = results['issues_by_type']
        
        return results
    
    def _get_scannable_files(self) -> List[Path]:
        """
        Get list of files to scan.
        
        Returns:
            List of Path objects for scannable files
        """
        files = []
        
        if self.target_path.is_file():
            if self.target_path.suffix in self.SCANNABLE_EXTENSIONS:
                files.append(self.target_path)
        else:
            for root, dirs, filenames in os.walk(self.target_path):
                # Skip common non-code directories
                dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build'}]
                
                for filename in filenames:
                    file_path = Path(root) / filename
                    if file_path.suffix in self.SCANNABLE_EXTENSIONS:
                        files.append(file_path)
        
        return files
    
    def _scan_file(self, file_path: Path) -> Dict[str, int]:
        """
        Scan a single file for security issues.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dictionary mapping issue types to counts
        """
        issues = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for each pattern type
            for issue_type, patterns in self.SECURITY_PATTERNS.items():
                count = 0
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                    count += len(matches)
                
                if count > 0:
                    issues[issue_type] = count
        
        except Exception as e:
            # Skip files that can't be read
            pass
        
        return issues
    
    def analyze(self) -> Dict[str, Any]:
        """
        Analyze the scan results.
        
        Returns:
            Dictionary containing analysis with strengths, weaknesses, and recommendations
        """
        analysis = {
            'strengths': [],
            'weaknesses': [],
            'recommendations': [],
            'summary': {}
        }
        
        total_issues = sum(self.issues_found.values())
        
        # Summary statistics
        analysis['summary']['files_scanned'] = self.files_scanned
        analysis['summary']['total_issues'] = total_issues
        analysis['summary']['issues_by_severity'] = self._categorize_by_severity()
        
        # Determine strengths
        if total_issues == 0:
            analysis['strengths'].append("No security issues detected in the scanned code")
        elif total_issues < 5:
            analysis['strengths'].append("Very few security issues detected")
        
        critical_issues = ['hardcoded_password', 'api_key', 'secret_token', 'sql_injection', 'command_injection']
        has_critical = any(self.issues_found.get(issue, 0) > 0 for issue in critical_issues)
        
        if not has_critical:
            analysis['strengths'].append("No critical security vulnerabilities found")
        
        if self.files_scanned > 0:
            analysis['strengths'].append(f"Successfully scanned {self.files_scanned} code files")
        
        # Determine weaknesses
        for issue_type, count in self.issues_found.items():
            if count > 0:
                weakness = self._get_issue_description(issue_type, count)
                analysis['weaknesses'].append(weakness)
        
        if not analysis['weaknesses']:
            analysis['weaknesses'].append("No significant security weaknesses detected")
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations()
        
        return analysis
    
    def _categorize_by_severity(self) -> Dict[str, int]:
        """Categorize issues by severity level."""
        severity = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        critical = ['hardcoded_password', 'api_key', 'secret_token', 'sql_injection', 'command_injection']
        high = ['weak_crypto']
        medium = ['insecure_random', 'insecure_file_operations']
        
        for issue_type, count in self.issues_found.items():
            if issue_type in critical:
                severity['critical'] += count
            elif issue_type in high:
                severity['high'] += count
            elif issue_type in medium:
                severity['medium'] += count
            else:
                severity['low'] += count
        
        return severity
    
    def _get_issue_description(self, issue_type: str, count: int) -> str:
        """Get a human-readable description of an issue."""
        descriptions = {
            'hardcoded_password': f"Found {count} hardcoded password(s) in source code",
            'api_key': f"Found {count} hardcoded API key(s) in source code",
            'secret_token': f"Found {count} hardcoded secret/token(s) in source code",
            'sql_injection': f"Found {count} potential SQL injection vulnerability(ies)",
            'command_injection': f"Found {count} potential command injection vulnerability(ies)",
            'weak_crypto': f"Found {count} usage(s) of weak cryptographic algorithms",
            'insecure_random': f"Found {count} usage(s) of insecure random number generation",
            'insecure_file_operations': f"Found {count} potentially insecure file operation(s)",
        }
        return descriptions.get(issue_type, f"Found {count} {issue_type} issue(s)")
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        if self.issues_found.get('hardcoded_password', 0) > 0 or \
           self.issues_found.get('api_key', 0) > 0 or \
           self.issues_found.get('secret_token', 0) > 0:
            recommendations.append(
                "Use environment variables or secure credential management systems "
                "(e.g., AWS Secrets Manager, HashiCorp Vault) instead of hardcoding secrets"
            )
        
        if self.issues_found.get('sql_injection', 0) > 0:
            recommendations.append(
                "Use parameterized queries or prepared statements to prevent SQL injection"
            )
        
        if self.issues_found.get('command_injection', 0) > 0:
            recommendations.append(
                "Avoid using system commands with user input. Use safer alternatives like "
                "subprocess with shell=False and proper input validation"
            )
        
        if self.issues_found.get('weak_crypto', 0) > 0:
            recommendations.append(
                "Replace weak cryptographic algorithms (MD5, SHA1, DES) with stronger "
                "alternatives like SHA-256, AES-256, or bcrypt for password hashing"
            )
        
        if self.issues_found.get('insecure_random', 0) > 0:
            recommendations.append(
                "Use cryptographically secure random number generators "
                "(e.g., secrets module in Python) for security-sensitive operations"
            )
        
        if self.issues_found.get('insecure_file_operations', 0) > 0:
            recommendations.append(
                "Implement proper input validation and use safe deserialization methods. "
                "Consider using safe_load for YAML and avoid pickle when possible"
            )
        
        if not recommendations:
            recommendations.append(
                "Continue following security best practices and conduct regular security audits"
            )
            recommendations.append(
                "Consider implementing automated security scanning in your CI/CD pipeline"
            )
        
        return recommendations
    
    def calculate_score(self) -> float:
        """
        Calculate security score based on findings.
        
        Returns:
            Score between 0.0 and 100.0
        """
        if self.files_scanned == 0:
            return 0.0
        
        # Weight issues by severity
        severity_weights = {
            'critical': 10.0,
            'high': 5.0,
            'medium': 2.0,
            'low': 1.0
        }
        
        severity_counts = self._categorize_by_severity()
        
        # Calculate weighted penalty
        weighted_issues = sum(
            count * severity_weights[severity]
            for severity, count in severity_counts.items()
        )
        
        # Calculate base score (penalize based on issues per file)
        issues_per_file = weighted_issues / self.files_scanned
        
        # Score calculation: start at 100, subtract penalties
        # Each weighted issue per file reduces score
        score = 100.0 - (issues_per_file * 5.0)
        
        # Apply floor and ceiling
        score = max(0.0, min(100.0, score))
        
        return score


def main():
    """Example usage of the Security Scanner."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <path_to_scan>")
        sys.exit(1)
    
    target_path = sys.argv[1]
    
    scanner = SecurityScanner(target_path)
    results = scanner.run()
    
    print(f"\nSecurity Scan Results for: {target_path}")
    print(f"Score: {results['score']:.1f}/100")
    print(f"Grade: {results['grade']}")
    print(f"\nFiles scanned: {results['analysis']['summary']['files_scanned']}")
    print(f"Total issues: {results['analysis']['summary']['total_issues']}")
    
    print("\nIssues by Severity:")
    for severity, count in results['analysis']['summary']['issues_by_severity'].items():
        if count > 0:
            print(f"  {severity.capitalize()}: {count}")
    
    if results['analysis']['weaknesses']:
        print("\nWeaknesses:")
        for weakness in results['analysis']['weaknesses']:
            print(f"  - {weakness}")
    
    if results['analysis']['recommendations']:
        print("\nRecommendations:")
        for i, rec in enumerate(results['analysis']['recommendations'], 1):
            print(f"  {i}. {rec}")


if __name__ == '__main__':
    main()

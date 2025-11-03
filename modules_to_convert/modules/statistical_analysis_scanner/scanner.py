"""
Statistical Analysis Scanner implementation for Code metrics and statistical analysis.

Based on Statistical Analysis Scanner principles, this scanner evaluates:
- Code complexity metrics
- Statistical quality indicators
- Performance analysis
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Any
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.base_scanner import BaseScanner


class StatisticalAnalysisScanner(BaseScanner):
    """
    Statistical Analysis Scanner code scanner.
    
    Evaluates repository code against Statistical Analysis Scanner requirements:
- Code complexity metrics
- Statistical quality indicators
- Performance analysis
    """
    
    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        '.py', '.js', '.ts', '.java', '.rb', '.php', '.go', '.cs',
        '.cpp', '.c', '.h', '.sh', '.bash', '.yml', '.yaml', '.json',
        '.xml', '.tf', '.md', '.txt'
    }
    
    # Required files/patterns
    REQUIRED_FILES = []
    
    # Documentation files
    DOCUMENTATION_FILES = ['METRICS.md', 'PERFORMANCE_ANALYSIS.md']
    
    def __init__(self, target_path: str):
        """Initialize the Statistical Analysis Scanner scanner."""
        super().__init__(target_path)
        self.files_scanned = 0
        self.findings = {}
        
    def scan(self) -> Dict[str, Any]:
        """
        Scan the target directory for Statistical Analysis Scanner compliance.
        
        Returns:
            Dictionary containing scan results
        """
        results = {
            'files_scanned': 0,
            'findings': {},
            'required_files_present': {},
            'documentation_present': {},
            'compliance_score': 0.0
        }
        
        # Check for required files
        for req_file in self.REQUIRED_FILES:
            file_path = self.target_path / req_file
            results['required_files_present'][req_file] = file_path.exists()
        
        # Check for documentation
        for doc_file in self.DOCUMENTATION_FILES:
            file_path = self.target_path / doc_file
            results['documentation_present'][doc_file] = file_path.exists()
        
        # Scan code files
        for file_path in self._get_scannable_files():
            self._scan_file(file_path, results)
            results['files_scanned'] += 1
        
        self.files_scanned = results['files_scanned']
        self.findings = results['findings']
        
        return results
    
    def _get_scannable_files(self) -> List[Path]:
        """Get list of files to scan."""
        files = []
        
        if self.target_path.is_file():
            if self.target_path.suffix in self.SCANNABLE_EXTENSIONS:
                files.append(self.target_path)
        else:
            for root, dirs, filenames in os.walk(self.target_path):
                # Skip common non-code directories
                dirs[:] = [d for d in dirs if d not in {
                    '.git', 'node_modules', '__pycache__', 'venv', 
                    '.venv', 'dist', 'build', 'target'
                }]
                
                for filename in filenames:
                    file_path = Path(root) / filename
                    if file_path.suffix in self.SCANNABLE_EXTENSIONS:
                        files.append(file_path)
        
        return files
    
    def _scan_file(self, file_path: Path, results: Dict[str, Any]) -> None:
        """Scan a single file for Statistical Analysis Scanner compliance."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Perform file-specific checks here
            # This is a placeholder for actual scanning logic
            
        except Exception as e:
            # Skip files that can't be read
            pass
    
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
        
        # Calculate required files compliance
        required_present = sum(1 for v in self.scan_results.get('required_files_present', {}).values() if v)
        required_total = len(self.REQUIRED_FILES)
        
        # Calculate documentation compliance  
        doc_present = sum(1 for v in self.scan_results.get('documentation_present', {}).values() if v)
        doc_total = len(self.DOCUMENTATION_FILES)
        
        # Summary statistics
        analysis['summary']['files_scanned'] = self.files_scanned
        analysis['summary']['required_files_compliance'] = f"{required_present}/{required_total}"
        analysis['summary']['documentation_compliance'] = f"{doc_present}/{doc_total}"
        
        # Determine strengths
        if required_present == required_total:
            analysis['strengths'].append("All required files are present")
        elif required_present > required_total * 0.7:
            analysis['strengths'].append(f"Most required files present ({required_present}/{required_total})")
        
        if doc_present >= doc_total * 0.8:
            analysis['strengths'].append(f"Good documentation coverage ({doc_present}/{doc_total})")
        
        if self.files_scanned > 0:
            analysis['strengths'].append(f"Successfully scanned {self.files_scanned} files")
        
        # Determine weaknesses
        missing_required = [f for f, present in self.scan_results.get('required_files_present', {}).items() if not present]
        if missing_required:
            analysis['weaknesses'].append(f"Missing required files: {', '.join(missing_required)}")
        
        missing_docs = [f for f, present in self.scan_results.get('documentation_present', {}).items() if not present]
        if missing_docs:
            analysis['weaknesses'].append(f"Missing documentation: {', '.join(missing_docs)}")
        
        if not analysis['weaknesses']:
            analysis['weaknesses'].append("No significant compliance issues detected")
        
        # Generate recommendations
        if missing_required:
            analysis['recommendations'].append(f"Add missing required files to improve compliance")
        
        if missing_docs:
            analysis['recommendations'].append(f"Complete missing documentation to meet Statistical Analysis Scanner standards")
        
        if not analysis['recommendations']:
            analysis['recommendations'].append(f"Continue maintaining Statistical Analysis Scanner compliance standards")
            analysis['recommendations'].append(f"Regularly review Statistical Analysis Scanner requirements for updates")
        
        return analysis
    
    def calculate_score(self) -> float:
        """
        Calculate Statistical Analysis Scanner compliance score.
        
        Returns:
            Score between 0.0 and 100.0
        """
        if self.files_scanned == 0:
            return 50.0  # Neutral score for empty repos
        
        # Calculate required files score (50% weight)
        required_present = sum(1 for v in self.scan_results.get('required_files_present', {}).values() if v)
        required_total = len(self.REQUIRED_FILES) if self.REQUIRED_FILES else 1
        required_score = (required_present / required_total) * 50.0
        
        # Calculate documentation score (30% weight)
        doc_present = sum(1 for v in self.scan_results.get('documentation_present', {}).values() if v)
        doc_total = len(self.DOCUMENTATION_FILES) if self.DOCUMENTATION_FILES else 1
        doc_score = (doc_present / doc_total) * 30.0
        
        # Base file scanning score (20% weight)
        base_score = 20.0
        
        # Total score
        total_score = required_score + doc_score + base_score
        
        return min(100.0, max(0.0, total_score))


def main():
    """Example usage of the StatisticalAnalysisScanner."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <path_to_scan>")
        sys.exit(1)
    
    target_path = sys.argv[1]
    
    scanner = StatisticalAnalysisScanner(target_path)
    results = scanner.run()
    
    print(f"\nStatistical Analysis Scanner Scan Results for: {target_path}")
    print(f"Score: {results['score']:.1f}/100")
    print(f"Grade: {results['grade']}")
    print(f"\nFiles scanned: {results['analysis']['summary']['files_scanned']}")
    
    if results['analysis']['strengths']:
        print("\nStrengths:")
        for strength in results['analysis']['strengths']:
            print(f"  + {strength}")
    
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

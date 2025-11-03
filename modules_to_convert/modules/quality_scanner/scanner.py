"""
Quality Scanner implementation for assessing code quality.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Any
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.base_scanner import BaseScanner
from common.grading import GradingSystem


class QualityScanner(BaseScanner):
    """
    Code quality scanner based on BSI IT-Grundschutz principles.
    
    Assesses:
- Code complexity
- Documentation quality
- Code organization
- Maintainability indicators
    """
    
    # File extensions for code files
    CODE_EXTENSIONS = {
        '.py', '.js', '.ts', '.java', '.rb', '.php', '.go', '.cs',
        '.cpp', '.c', '.h', '.rs', '.swift', '.kt'
    }
    
    # Documentation file patterns
    DOC_PATTERNS = ['README', 'CONTRIBUTING', 'CHANGELOG', 'INSTALL', 'USAGE']
    
    def __init__(self, target_path: str):
        """Initialize the quality scanner."""
        super().__init__(target_path)
        self.code_metrics = {}
    
    def scan(self) -> Dict[str, Any]:
        """
        Scan code for quality metrics.
        
        Returns:
            Dictionary containing scan results
        """
        results = {
            'code_files': 0,
            'total_lines': 0,
            'comment_lines': 0,
            'blank_lines': 0,
            'code_lines': 0,
            'documentation_files': 0,
            'average_function_length': 0,
            'long_functions': 0,
            'deeply_nested_blocks': 0,
            'files_by_extension': {},
        }
        
        function_lengths = []
        
        for file_path in self._get_code_files():
            file_metrics = self._analyze_file(file_path)
            
            results['code_files'] += 1
            results['total_lines'] += file_metrics['total_lines']
            results['comment_lines'] += file_metrics['comment_lines']
            results['blank_lines'] += file_metrics['blank_lines']
            results['code_lines'] += file_metrics['code_lines']
            results['long_functions'] += file_metrics['long_functions']
            results['deeply_nested_blocks'] += file_metrics['deeply_nested_blocks']
            
            function_lengths.extend(file_metrics['function_lengths'])
            
            # Track by extension
            ext = file_path.suffix
            results['files_by_extension'][ext] = results['files_by_extension'].get(ext, 0) + 1
        
        # Calculate averages
        if function_lengths:
            results['average_function_length'] = sum(function_lengths) / len(function_lengths)
        
        # Check documentation
        results['documentation_files'] = self._count_documentation_files()
        
        # Calculate comment ratio
        if results['total_lines'] > 0:
            results['comment_ratio'] = results['comment_lines'] / results['total_lines']
        else:
            results['comment_ratio'] = 0.0
        
        self.code_metrics = results
        
        return results
    
    def _get_code_files(self) -> List[Path]:
        """Get list of code files to analyze."""
        files = []
        
        if self.target_path.is_file():
            if self.target_path.suffix in self.CODE_EXTENSIONS:
                files.append(self.target_path)
        else:
            for root, dirs, filenames in os.walk(self.target_path):
                # Skip non-code directories
                dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'venv', '.venv', 'dist', 'build'}]
                
                for filename in filenames:
                    file_path = Path(root) / filename
                    if file_path.suffix in self.CODE_EXTENSIONS:
                        files.append(file_path)
        
        return files
    
    def _analyze_file(self, file_path: Path) -> Dict[str, Any]:
        """Analyze a single code file."""
        metrics = {
            'total_lines': 0,
            'code_lines': 0,
            'comment_lines': 0,
            'blank_lines': 0,
            'function_lengths': [],
            'long_functions': 0,
            'deeply_nested_blocks': 0,
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            metrics['total_lines'] = len(lines)
            
            current_function_length = 0
            in_function = False
            max_nesting = 0
            current_nesting = 0
            
            for line in lines:
                stripped = line.strip()
                
                # Count blank lines
                if not stripped:
                    metrics['blank_lines'] += 1
                    continue
                
                # Count comment lines (basic detection)
                if stripped.startswith('#') or \
                   stripped.startswith('//') or \
                   stripped.startswith('/*') or \
                   stripped.startswith('*'):
                    metrics['comment_lines'] += 1
                    continue
                
                # Otherwise it's code
                metrics['code_lines'] += 1
                
                # Detect functions (basic detection)
                if re.match(r'\s*(def|function|func|public|private|protected)\s+\w+', line):
                    if in_function and current_function_length > 0:
                        metrics['function_lengths'].append(current_function_length)
                        if current_function_length > 50:
                            metrics['long_functions'] += 1
                    in_function = True
                    current_function_length = 0
                
                if in_function:
                    current_function_length += 1
                
                # Detect nesting depth (basic - counts control flow structures)
                # NOTE: This is a simplified heuristic that works across languages
                # but may have false positives from non-control-flow colons/braces.
                # For production use, consider using language-specific AST parsing.
                if re.search(r'\b(if|for|while|def|function|class)\b.*[:{]', line):
                    current_nesting += 1
                    max_nesting = max(max_nesting, current_nesting)
                if '}' in line or (stripped and stripped[0] not in ' \t' and current_nesting > 0):
                    current_nesting = max(0, current_nesting - 1)
            
            # Final function
            if in_function and current_function_length > 0:
                metrics['function_lengths'].append(current_function_length)
                if current_function_length > 50:
                    metrics['long_functions'] += 1
            
            # Check for deeply nested code
            if max_nesting > 4:
                metrics['deeply_nested_blocks'] += 1
        
        except Exception:
            pass
        
        return metrics
    
    def _count_documentation_files(self) -> int:
        """Count documentation files in the project."""
        count = 0
        
        for root, dirs, files in os.walk(self.target_path):
            # Only check top-level and docs directories
            if root != str(self.target_path) and 'doc' not in root.lower():
                continue
            
            for filename in files:
                name_upper = filename.upper()
                if any(pattern in name_upper for pattern in self.DOC_PATTERNS):
                    count += 1
        
        return count
    
    def analyze(self) -> Dict[str, Any]:
        """
        Analyze code quality metrics.
        
        Returns:
            Dictionary containing analysis
        """
        analysis = {
            'strengths': [],
            'weaknesses': [],
            'recommendations': [],
            'summary': {}
        }
        
        # Summary
        analysis['summary']['code_files'] = self.code_metrics.get('code_files', 0)
        analysis['summary']['total_lines'] = self.code_metrics.get('total_lines', 0)
        analysis['summary']['code_lines'] = self.code_metrics.get('code_lines', 0)
        analysis['summary']['comment_ratio'] = f"{self.code_metrics.get('comment_ratio', 0) * 100:.1f}%"
        analysis['summary']['documentation_files'] = self.code_metrics.get('documentation_files', 0)
        
        # Strengths
        comment_ratio = self.code_metrics.get('comment_ratio', 0)
        if comment_ratio > 0.15:
            analysis['strengths'].append(f"Good code documentation with {comment_ratio*100:.1f}% comment ratio")
        
        doc_files = self.code_metrics.get('documentation_files', 0)
        if doc_files > 2:
            analysis['strengths'].append(f"Comprehensive project documentation ({doc_files} documentation files)")
        
        long_functions = self.code_metrics.get('long_functions', 0)
        if long_functions == 0:
            analysis['strengths'].append("No overly long functions detected")
        
        nested_blocks = self.code_metrics.get('deeply_nested_blocks', 0)
        if nested_blocks == 0:
            analysis['strengths'].append("No deeply nested code blocks detected")
        
        code_files = self.code_metrics.get('code_files', 0)
        if code_files > 0:
            analysis['strengths'].append(f"Analyzed {code_files} code files")
        
        if not analysis['strengths']:
            analysis['strengths'].append("Basic code structure is present")
        
        # Weaknesses
        if comment_ratio < 0.10:
            analysis['weaknesses'].append(f"Low code documentation ({comment_ratio*100:.1f}% comment ratio)")
        
        if doc_files < 2:
            analysis['weaknesses'].append(f"Limited project documentation ({doc_files} documentation files)")
        
        if long_functions > 0:
            analysis['weaknesses'].append(f"Found {long_functions} overly long function(s) (>50 lines)")
        
        if nested_blocks > 0:
            analysis['weaknesses'].append(f"Found {nested_blocks} file(s) with deeply nested code (>4 levels)")
        
        avg_func_length = self.code_metrics.get('average_function_length', 0)
        if avg_func_length > 30:
            analysis['weaknesses'].append(f"Average function length is high ({avg_func_length:.1f} lines)")
        
        if code_files == 0:
            analysis['weaknesses'].append("No code files found to analyze")
        
        if not analysis['weaknesses']:
            analysis['weaknesses'].append("No significant quality issues detected")
        
        # Recommendations
        analysis['recommendations'] = self._generate_recommendations()
        
        return analysis
    
    def _generate_recommendations(self) -> List[str]:
        """Generate quality recommendations."""
        recommendations = []
        
        comment_ratio = self.code_metrics.get('comment_ratio', 0)
        if comment_ratio < 0.10:
            recommendations.append(
                "Add more inline comments and docstrings to improve code documentation"
            )
        
        doc_files = self.code_metrics.get('documentation_files', 0)
        if doc_files < 2:
            recommendations.append(
                "Create comprehensive documentation including README, CONTRIBUTING, and API docs"
            )
        
        long_functions = self.code_metrics.get('long_functions', 0)
        if long_functions > 0:
            recommendations.append(
                "Refactor long functions into smaller, more focused functions for better maintainability"
            )
        
        nested_blocks = self.code_metrics.get('deeply_nested_blocks', 0)
        if nested_blocks > 0:
            recommendations.append(
                "Reduce code complexity by extracting deeply nested blocks into separate functions"
            )
        
        avg_func_length = self.code_metrics.get('average_function_length', 0)
        if avg_func_length > 30:
            recommendations.append(
                "Consider breaking down functions to keep average function length under 25-30 lines"
            )
        
        if not recommendations:
            recommendations.append(
                "Maintain current code quality standards"
            )
            recommendations.append(
                "Consider implementing code quality tools like linters and formatters"
            )
            recommendations.append(
                "Conduct regular code reviews to ensure consistent quality"
            )
        
        return recommendations
    
    def calculate_score(self) -> float:
        """
        Calculate quality score.
        
        Returns:
            Score between 0.0 and 100.0
        """
        if self.code_metrics.get('code_files', 0) == 0:
            return 0.0
        
        # Component scores
        components = {}
        
        # Documentation score (weight: 30%)
        comment_ratio = self.code_metrics.get('comment_ratio', 0)
        doc_files = self.code_metrics.get('documentation_files', 0)
        doc_score = (min(comment_ratio / 0.20, 1.0) * 50) + (min(doc_files / 3, 1.0) * 50)
        components['documentation'] = (doc_score, 30.0)
        
        # Complexity score (weight: 40%)
        long_functions = self.code_metrics.get('long_functions', 0)
        nested_blocks = self.code_metrics.get('deeply_nested_blocks', 0)
        code_files = self.code_metrics.get('code_files', 1)
        
        complexity_issues = (long_functions + nested_blocks) / code_files
        complexity_score = max(0, 100 - (complexity_issues * 20))
        components['complexity'] = (complexity_score, 40.0)
        
        # Organization score (weight: 30%)
        # Based on presence of proper structure
        org_score = 100.0
        if doc_files < 2:
            org_score -= 20
        if comment_ratio < 0.05:
            org_score -= 30
        
        components['organization'] = (max(0, org_score), 30.0)
        
        # Calculate weighted score
        score = GradingSystem.calculate_weighted_score(components)
        
        return score


def main():
    """Example usage of the Quality Scanner."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <path_to_scan>")
        sys.exit(1)
    
    target_path = sys.argv[1]
    
    scanner = QualityScanner(target_path)
    results = scanner.run()
    
    print(f"\nQuality Scan Results for: {target_path}")
    print(f"Score: {results['score']:.1f}/100")
    print(f"Grade: {results['grade']}")
    print(f"\nCode files: {results['analysis']['summary']['code_files']}")
    print(f"Total lines: {results['analysis']['summary']['total_lines']}")
    print(f"Comment ratio: {results['analysis']['summary']['comment_ratio']}")
    print(f"Documentation files: {results['analysis']['summary']['documentation_files']}")
    
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

"""
Compliance Scanner implementation for checking code compliance with standards.
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


class ComplianceScanner(BaseScanner):
    """
    Compliance-focused code scanner based on STIG principles.
    
    Checks for:
- Required documentation (README, LICENSE, etc.)
- Code structure and organization
- Configuration file security
- Dependency management
- Version control practices
    """
    
    # Required files for compliance
    # NOTE: These are general best practices. Organizations may want to customize
    # these requirements based on their specific compliance needs or frameworks.
    REQUIRED_FILES = {
        'README.md': 'Project documentation',
        'LICENSE': 'License file',
    }
    
    # Recommended files
    RECOMMENDED_FILES = {
        '.gitignore': 'Git ignore file',
        'CONTRIBUTING.md': 'Contribution guidelines',
        'CHANGELOG.md': 'Change log',
        'CODE_OF_CONDUCT.md': 'Code of conduct',
    }
    
    # Insecure configuration patterns
    INSECURE_CONFIG_PATTERNS = {
        'debug_mode': [
            r'DEBUG\s*=\s*True',
            r'debug:\s*true',
        ],
        'insecure_ssl': [
            r'verify\s*=\s*False',
            r'ssl_verify:\s*false',
        ],
        'exposed_secrets': [
            r'password\s*[:=]',
            r'secret\s*[:=]',
            r'token\s*[:=]',
        ],
    }
    
    def __init__(self, target_path: str):
        """Initialize the compliance scanner."""
        super().__init__(target_path)
        self.compliance_checks = {}
    
    def scan(self) -> Dict[str, Any]:
        """
        Scan the target for compliance issues.
        
        Returns:
            Dictionary containing scan results
        """
        results = {
            'documentation_compliance': self._check_documentation(),
            'structure_compliance': self._check_structure(),
            'configuration_compliance': self._check_configurations(),
            'dependency_compliance': self._check_dependencies(),
            'total_checks': 0,
            'passed_checks': 0,
            'failed_checks': 0,
        }
        
        # Count total checks
        for category in ['documentation_compliance', 'structure_compliance', 
                        'configuration_compliance', 'dependency_compliance']:
            category_data = results[category]
            results['total_checks'] += category_data.get('total', 0)
            results['passed_checks'] += category_data.get('passed', 0)
            results['failed_checks'] += category_data.get('failed', 0)
        
        self.compliance_checks = results
        
        return results
    
    def _check_documentation(self) -> Dict[str, Any]:
        """Check for required and recommended documentation files."""
        result = {
            'required': {},
            'recommended': {},
            'total': 0,
            'passed': 0,
            'failed': 0,
        }
        
        # Check required files
        for filename, description in self.REQUIRED_FILES.items():
            file_path = self.target_path / filename
            exists = file_path.exists()
            result['required'][filename] = {
                'exists': exists,
                'description': description
            }
            result['total'] += 1
            if exists:
                result['passed'] += 1
            else:
                result['failed'] += 1
        
        # Check recommended files
        for filename, description in self.RECOMMENDED_FILES.items():
            file_path = self.target_path / filename
            exists = file_path.exists()
            result['recommended'][filename] = {
                'exists': exists,
                'description': description
            }
        
        return result
    
    def _check_structure(self) -> Dict[str, Any]:
        """Check code structure and organization."""
        result = {
            'has_src_directory': False,
            'has_tests_directory': False,
            'has_docs_directory': False,
            'has_config_files': False,
            'total': 4,
            'passed': 0,
            'failed': 0,
        }
        
        # Check for common directory structures
        if (self.target_path / 'src').exists() or (self.target_path / 'lib').exists():
            result['has_src_directory'] = True
            result['passed'] += 1
        else:
            result['failed'] += 1
        
        if (self.target_path / 'tests').exists() or (self.target_path / 'test').exists():
            result['has_tests_directory'] = True
            result['passed'] += 1
        else:
            result['failed'] += 1
        
        if (self.target_path / 'docs').exists() or (self.target_path / 'documentation').exists():
            result['has_docs_directory'] = True
            result['passed'] += 1
        else:
            result['failed'] += 1
        
        # Check for configuration files
        config_files = ['.editorconfig', 'setup.py', 'pyproject.toml', 'package.json', 
                       'Cargo.toml', 'pom.xml', 'build.gradle']
        has_config = any((self.target_path / cf).exists() for cf in config_files)
        if has_config:
            result['has_config_files'] = True
            result['passed'] += 1
        else:
            result['failed'] += 1
        
        return result
    
    def _check_configurations(self) -> Dict[str, Any]:
        """Check configuration files for security issues."""
        result = {
            'config_files_scanned': 0,
            'insecure_configs': {},
            'total': 1,  # At least check if config files exist
            'passed': 0,
            'failed': 0,
        }
        
        config_extensions = {'.yml', '.yaml', '.json', '.ini', '.conf', '.config', '.env'}
        insecure_count = 0
        
        for file_path in self._get_config_files(config_extensions):
            result['config_files_scanned'] += 1
            issues = self._scan_config_file(file_path)
            if issues:
                result['insecure_configs'][str(file_path)] = issues
                insecure_count += len(issues)
        
        if insecure_count == 0:
            result['passed'] = 1
        else:
            result['failed'] = 1
        
        return result
    
    def _get_config_files(self, extensions: set) -> List[Path]:
        """Get list of configuration files."""
        files = []
        
        for root, dirs, filenames in os.walk(self.target_path):
            # Skip non-relevant directories
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'venv', '.venv'}]
            
            for filename in filenames:
                file_path = Path(root) / filename
                if file_path.suffix in extensions or filename.startswith('.env'):
                    files.append(file_path)
        
        return files
    
    def _scan_config_file(self, file_path: Path) -> List[str]:
        """Scan a configuration file for issues."""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for insecure patterns
            for issue_type, patterns in self.INSECURE_CONFIG_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        issues.append(issue_type)
                        break
        except Exception:
            pass
        
        return issues
    
    def _check_dependencies(self) -> Dict[str, Any]:
        """Check dependency management compliance."""
        result = {
            'has_dependency_file': False,
            'dependency_file_type': None,
            'total': 1,
            'passed': 0,
            'failed': 0,
        }
        
        dependency_files = {
            'requirements.txt': 'Python',
            'Pipfile': 'Python',
            'package.json': 'JavaScript/Node.js',
            'Gemfile': 'Ruby',
            'Cargo.toml': 'Rust',
            'go.mod': 'Go',
            'pom.xml': 'Java/Maven',
            'build.gradle': 'Java/Gradle',
        }
        
        for filename, language in dependency_files.items():
            if (self.target_path / filename).exists():
                result['has_dependency_file'] = True
                result['dependency_file_type'] = language
                result['passed'] = 1
                break
        
        if not result['has_dependency_file']:
            result['failed'] = 1
        
        return result
    
    def analyze(self) -> Dict[str, Any]:
        """
        Analyze the compliance scan results.
        
        Returns:
            Dictionary containing analysis
        """
        analysis = {
            'strengths': [],
            'weaknesses': [],
            'recommendations': [],
            'summary': {}
        }
        
        total = self.compliance_checks.get('total_checks', 0)
        passed = self.compliance_checks.get('passed_checks', 0)
        failed = self.compliance_checks.get('failed_checks', 0)
        
        # Summary
        analysis['summary']['total_checks'] = total
        analysis['summary']['passed_checks'] = passed
        analysis['summary']['failed_checks'] = failed
        if total > 0:
            analysis['summary']['compliance_rate'] = f"{(passed/total)*100:.1f}%"
        else:
            analysis['summary']['compliance_rate'] = "0%"
        
        # Strengths
        doc_compliance = self.compliance_checks.get('documentation_compliance', {})
        if doc_compliance.get('required', {}).get('README.md', {}).get('exists'):
            analysis['strengths'].append("Project has README documentation")
        
        if doc_compliance.get('required', {}).get('LICENSE', {}).get('exists'):
            analysis['strengths'].append("Project has LICENSE file")
        
        struct = self.compliance_checks.get('structure_compliance', {})
        if struct.get('has_tests_directory'):
            analysis['strengths'].append("Project has dedicated tests directory")
        
        config = self.compliance_checks.get('configuration_compliance', {})
        if not config.get('insecure_configs'):
            analysis['strengths'].append("No insecure configuration patterns detected")
        
        dep = self.compliance_checks.get('dependency_compliance', {})
        if dep.get('has_dependency_file'):
            analysis['strengths'].append(f"Project uses dependency management ({dep.get('dependency_file_type')})")
        
        if not analysis['strengths']:
            analysis['strengths'].append("Project structure is minimal and could be improved")
        
        # Weaknesses
        for filename, info in doc_compliance.get('required', {}).items():
            if not info.get('exists'):
                analysis['weaknesses'].append(f"Missing required file: {filename}")
        
        missing_recommended = [
            filename for filename, info in doc_compliance.get('recommended', {}).items()
            if not info.get('exists')
        ]
        if missing_recommended:
            analysis['weaknesses'].append(
                f"Missing recommended files: {', '.join(missing_recommended)}"
            )
        
        if not struct.get('has_src_directory'):
            analysis['weaknesses'].append("No dedicated source code directory (src/ or lib/)")
        
        if not struct.get('has_tests_directory'):
            analysis['weaknesses'].append("No dedicated tests directory")
        
        if config.get('insecure_configs'):
            count = len(config['insecure_configs'])
            analysis['weaknesses'].append(f"Found {count} configuration file(s) with security issues")
        
        if not dep.get('has_dependency_file'):
            analysis['weaknesses'].append("No dependency management file found")
        
        if not analysis['weaknesses']:
            analysis['weaknesses'].append("No significant compliance issues detected")
        
        # Recommendations
        analysis['recommendations'] = self._generate_recommendations()
        
        return analysis
    
    def _generate_recommendations(self) -> List[str]:
        """Generate compliance recommendations."""
        recommendations = []
        
        doc_compliance = self.compliance_checks.get('documentation_compliance', {})
        
        # Required files
        for filename, info in doc_compliance.get('required', {}).items():
            if not info.get('exists'):
                recommendations.append(
                    f"Add {filename}: {info.get('description', 'Required file')}"
                )
        
        # Recommended files
        missing_recommended = [
            filename for filename, info in doc_compliance.get('recommended', {}).items()
            if not info.get('exists')
        ]
        if missing_recommended and len(recommendations) < 3:
            recommendations.append(
                f"Consider adding recommended documentation: {', '.join(missing_recommended[:2])}"
            )
        
        struct = self.compliance_checks.get('structure_compliance', {})
        if not struct.get('has_tests_directory'):
            recommendations.append(
                "Create a tests/ directory and add automated tests"
            )
        
        if not struct.get('has_src_directory'):
            recommendations.append(
                "Organize code into a src/ or lib/ directory for better structure"
            )
        
        config = self.compliance_checks.get('configuration_compliance', {})
        if config.get('insecure_configs'):
            recommendations.append(
                "Review and secure configuration files - avoid debug mode in production "
                "and never commit secrets"
            )
        
        dep = self.compliance_checks.get('dependency_compliance', {})
        if not dep.get('has_dependency_file'):
            recommendations.append(
                "Add a dependency management file (e.g., requirements.txt, package.json)"
            )
        
        if not recommendations:
            recommendations.append(
                "Maintain current compliance standards and review regularly"
            )
            recommendations.append(
                "Consider implementing additional compliance checks specific to your industry"
            )
        
        return recommendations
    
    def calculate_score(self) -> float:
        """
        Calculate compliance score.
        
        Returns:
            Score between 0.0 and 100.0
        """
        total = self.compliance_checks.get('total_checks', 0)
        passed = self.compliance_checks.get('passed_checks', 0)
        
        if total == 0:
            return 0.0
        
        # Base score from pass rate
        base_score = (passed / total) * 100
        
        # Bonus points for recommended items
        doc_compliance = self.compliance_checks.get('documentation_compliance', {})
        recommended_count = sum(
            1 for info in doc_compliance.get('recommended', {}).values()
            if info.get('exists')
        )
        bonus = recommended_count * 2  # 2 points per recommended file
        
        score = base_score + bonus
        
        # Apply ceiling
        score = min(100.0, score)
        
        return score


def main():
    """Example usage of the Compliance Scanner."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <path_to_scan>")
        sys.exit(1)
    
    target_path = sys.argv[1]
    
    scanner = ComplianceScanner(target_path)
    results = scanner.run()
    
    print(f"\nCompliance Scan Results for: {target_path}")
    print(f"Score: {results['score']:.1f}/100")
    print(f"Grade: {results['grade']}")
    print(f"\nCompliance Rate: {results['analysis']['summary']['compliance_rate']}")
    print(f"Checks Passed: {results['analysis']['summary']['passed_checks']}/{results['analysis']['summary']['total_checks']}")
    
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

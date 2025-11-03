"""
Repository metadata module for extracting repository information.

This module demonstrates how to create a module that analyzes repository metadata.
"""

import os
import json
from typing import Dict, Any, List
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from module_base import ModuleBase


class RepoMetadataModule(ModuleBase):
    """
    Repository metadata extraction module.
    
    This module analyzes repository structure and extracts metadata such as:
    - File types and counts
    - Directory structure
    - Configuration files present
    - Language detection
    """
    
    def get_name(self) -> str:
        """Return the module name."""
        return "repo_metadata"
    
    def get_version(self) -> str:
        """Return the module version."""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Return the module description."""
        return "Extracts and analyzes repository metadata and structure"
    
    def initialize(self) -> bool:
        """Initialize the metadata module."""
        self.config_files = [
            'package.json', 'requirements.txt', 'setup.py', 'pom.xml',
            'Gemfile', 'Cargo.toml', 'go.mod', 'composer.json'
        ]
        
        self.language_extensions = {
            'Python': ['.py'],
            'JavaScript': ['.js', '.jsx'],
            'TypeScript': ['.ts', '.tsx'],
            'Java': ['.java'],
            'C++': ['.cpp', '.cc', '.cxx', '.hpp', '.h'],
            'C': ['.c', '.h'],
            'Go': ['.go'],
            'Ruby': ['.rb'],
            'PHP': ['.php'],
            'Rust': ['.rs'],
        }
        
        return True
    
    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the metadata extraction.
        
        Args:
            **kwargs: Can include:
                - path: Path to analyze (default: current directory)
                - recursive: Whether to scan recursively (default: True)
        
        Returns:
            Dictionary with metadata results
        """
        path = kwargs.get('path', '.')
        recursive = kwargs.get('recursive', True)
        
        if not os.path.exists(path):
            return {
                'error': f"Path not found: {path}",
                'success': False
            }
        
        results = {
            'path': os.path.abspath(path),
            'file_types': {},
            'languages': {},
            'config_files': [],
            'total_files': 0,
            'total_directories': 0,
            'success': True
        }
        
        self._analyze_path(path, results, recursive)
        
        # Calculate percentages
        if results['total_files'] > 0:
            for lang in results['languages']:
                count = results['languages'][lang]
                results['languages'][lang] = {
                    'count': count,
                    'percentage': round((count / results['total_files']) * 100, 2)
                }
        
        return results
    
    def _analyze_path(self, path: str, results: Dict[str, Any], recursive: bool) -> None:
        """
        Analyze a path and update results.
        
        Args:
            path: Path to analyze
            results: Results dictionary to update
            recursive: Whether to scan recursively
        """
        try:
            if os.path.isfile(path):
                self._process_file(path, results)
            elif os.path.isdir(path):
                results['total_directories'] += 1
                for item in os.listdir(path):
                    # Skip hidden and ignored directories
                    if item.startswith('.') or item in ['node_modules', 'venv', '__pycache__', 'dist', 'build']:
                        continue
                    
                    item_path = os.path.join(path, item)
                    
                    if os.path.isfile(item_path):
                        self._process_file(item_path, results)
                        
                        # Check for config files
                        if item in self.config_files:
                            results['config_files'].append(item_path)
                    
                    elif os.path.isdir(item_path) and recursive:
                        self._analyze_path(item_path, results, recursive)
        except Exception as e:
            # Silently skip files/directories that can't be accessed
            pass
    
    def _process_file(self, file_path: str, results: Dict[str, Any]) -> None:
        """
        Process a single file and update results.
        
        Args:
            file_path: Path to the file
            results: Results dictionary to update
        """
        results['total_files'] += 1
        
        # Get file extension
        ext = Path(file_path).suffix
        if ext:
            results['file_types'][ext] = results['file_types'].get(ext, 0) + 1
            
            # Detect language
            for lang, extensions in self.language_extensions.items():
                if ext in extensions:
                    results['languages'][lang] = results['languages'].get(lang, 0) + 1
                    break
    
    def get_dependencies(self) -> List[str]:
        """Return list of module dependencies."""
        return []

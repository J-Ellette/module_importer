"""
Module container format support for multi-file modules.

A .module file is a ZIP archive with the following structure:
    module_name.module (ZIP file)
    ├── module.json           # Module metadata and configuration
    ├── __init__.py          # Main module entry point (must contain ModuleBase subclass)
    ├── other_files.py       # Additional Python files
    ├── resources/           # Resources directory (optional)
    │   ├── data.json
    │   └── templates/
    └── README.md            # Module documentation (optional)
"""

import os
import zipfile
import json
import tempfile
import shutil
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
import logging

from module_base import ModuleBase

logger = logging.getLogger(__name__)


class ModuleContainer:
    """
    Represents a module container (.module file).
    
    Handles loading, validation, and extraction of module containers.
    """
    
    REQUIRED_FILES = ['module.json', '__init__.py']
    CONTAINER_EXTENSION = '.module'
    
    def __init__(self, container_path: str):
        """
        Initialize module container.
        
        Args:
            container_path: Path to the .module file
            
        Raises:
            ValueError: If container is invalid
        """
        self.container_path = container_path
        self.metadata: Dict[str, Any] = {}
        self.extracted_path: Optional[str] = None
        self._temp_dir: Optional[str] = None
        
        if not os.path.exists(container_path):
            raise ValueError(f"Container file not found: {container_path}")
        
        if not self._is_valid_container():
            raise ValueError(f"Invalid module container: {container_path}")
        
        self._load_metadata()
    
    def _is_valid_container(self) -> bool:
        """
        Check if the container is a valid .module file.
        
        Returns:
            True if valid, False otherwise
        """
        try:
            if not zipfile.is_zipfile(self.container_path):
                return False
            
            with zipfile.ZipFile(self.container_path, 'r') as zf:
                file_list = zf.namelist()
                
                # Check for required files
                for required_file in self.REQUIRED_FILES:
                    if required_file not in file_list:
                        logger.error(f"Missing required file: {required_file}")
                        return False
                
                # Validate module.json
                try:
                    metadata_content = zf.read('module.json')
                    json.loads(metadata_content)
                except (json.JSONDecodeError, KeyError) as e:
                    logger.error(f"Invalid module.json: {e}")
                    return False
            
            return True
        except Exception as e:
            logger.error(f"Error validating container: {e}")
            return False
    
    def _load_metadata(self) -> None:
        """Load metadata from module.json."""
        with zipfile.ZipFile(self.container_path, 'r') as zf:
            metadata_content = zf.read('module.json')
            self.metadata = json.loads(metadata_content)
    
    def extract(self, target_dir: Optional[str] = None) -> str:
        """
        Extract the module container to a directory.
        
        Args:
            target_dir: Directory to extract to (uses temp dir if not provided)
            
        Returns:
            Path to extracted directory
        """
        if target_dir is None:
            self._temp_dir = tempfile.mkdtemp(prefix='module_')
            target_dir = self._temp_dir
        
        with zipfile.ZipFile(self.container_path, 'r') as zf:
            zf.extractall(target_dir)
        
        self.extracted_path = target_dir
        logger.info(f"Extracted module to: {target_dir}")
        return target_dir
    
    def cleanup(self) -> None:
        """Clean up extracted temporary files."""
        if self._temp_dir and os.path.exists(self._temp_dir):
            shutil.rmtree(self._temp_dir)
            logger.info(f"Cleaned up temporary directory: {self._temp_dir}")
            self._temp_dir = None
            self.extracted_path = None
    
    def get_entry_point(self) -> str:
        """
        Get the path to the module's entry point (__init__.py).
        
        Returns:
            Path to __init__.py
            
        Raises:
            RuntimeError: If module hasn't been extracted
        """
        if self.extracted_path is None:
            raise RuntimeError("Module must be extracted before getting entry point")
        
        return os.path.join(self.extracted_path, '__init__.py')
    
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get module metadata.
        
        Returns:
            Dictionary containing module metadata
        """
        return self.metadata.copy()
    
    def list_files(self) -> List[str]:
        """
        List all files in the container.
        
        Returns:
            List of file paths in the container
        """
        with zipfile.ZipFile(self.container_path, 'r') as zf:
            return zf.namelist()
    
    @staticmethod
    def create_container(source_dir: str, output_path: str, 
                        metadata: Dict[str, Any]) -> str:
        """
        Create a .module container from a directory.
        
        Args:
            source_dir: Directory containing module files
            output_path: Output path for .module file
            metadata: Module metadata dictionary
            
        Returns:
            Path to created container
            
        Raises:
            ValueError: If source directory is invalid
        """
        if not os.path.isdir(source_dir):
            raise ValueError(f"Source directory not found: {source_dir}")
        
        # Ensure __init__.py exists
        init_file = os.path.join(source_dir, '__init__.py')
        if not os.path.exists(init_file):
            raise ValueError(f"__init__.py not found in {source_dir}")
        
        # Ensure output has .module extension
        if not output_path.endswith(ModuleContainer.CONTAINER_EXTENSION):
            output_path += ModuleContainer.CONTAINER_EXTENSION
        
        # Create the container
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Write metadata
            zf.writestr('module.json', json.dumps(metadata, indent=2))
            
            # Write all files from source directory
            for root, dirs, files in os.walk(source_dir):
                # Skip hidden directories and __pycache__
                dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
                
                for file in files:
                    if file.startswith('.') or file.endswith('.pyc'):
                        continue
                    
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, source_dir)
                    zf.write(file_path, arcname)
        
        logger.info(f"Created module container: {output_path}")
        return output_path
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup resources."""
        self.cleanup()

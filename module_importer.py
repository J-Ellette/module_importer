"""
Module importer and registry for the CMS.

Provides functionality to dynamically load, register, and manage modules.
"""

import importlib
import importlib.util
import sys
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Type
import logging

from module_base import ModuleBase
from module_container import ModuleContainer


logger = logging.getLogger(__name__)


class ModuleRegistry:
    """
    Registry for managing loaded modules.
    """
    
    def __init__(self):
        """Initialize the module registry."""
        self._modules: Dict[str, ModuleBase] = {}
        self._module_paths: Dict[str, str] = {}
        self._module_containers: Dict[str, ModuleContainer] = {}
    
    def register(self, module: ModuleBase, source_path: Optional[str] = None, 
                 container: Optional[ModuleContainer] = None) -> None:
        """
        Register a module instance.
        
        Args:
            module: Module instance to register
            source_path: Optional path where module was loaded from
            container: Optional ModuleContainer if module was loaded from container
            
        Raises:
            ValueError: If module with same name already registered
        """
        name = module.get_name()
        if name in self._modules:
            raise ValueError(f"Module '{name}' is already registered")
        
        self._modules[name] = module
        if source_path:
            self._module_paths[name] = source_path
        if container:
            self._module_containers[name] = container
        
        logger.info(f"Registered module: {name} v{module.get_version()}")
    
    def unregister(self, name: str) -> None:
        """
        Unregister a module by name.
        
        Args:
            name: Name of the module to unregister
        """
        if name in self._modules:
            module = self._modules[name]
            module.shutdown()
            del self._modules[name]
            if name in self._module_paths:
                del self._module_paths[name]
            if name in self._module_containers:
                # Cleanup container resources
                container = self._module_containers[name]
                container.cleanup()
                del self._module_containers[name]
            logger.info(f"Unregistered module: {name}")
    
    def get(self, name: str) -> Optional[ModuleBase]:
        """
        Get a module by name.
        
        Args:
            name: Name of the module
            
        Returns:
            Module instance or None if not found
        """
        return self._modules.get(name)
    
    def list_modules(self) -> List[str]:
        """
        Get list of all registered module names.
        
        Returns:
            List of module names
        """
        return list(self._modules.keys())
    
    def get_all_info(self) -> List[Dict[str, Any]]:
        """
        Get information about all registered modules.
        
        Returns:
            List of dictionaries containing module information
        """
        return [module.get_info() for module in self._modules.values()]
    
    def clear(self) -> None:
        """Unregister all modules."""
        for name in list(self._modules.keys()):
            self.unregister(name)


class ModuleImporter:
    """
    Module importer for dynamically loading modules.
    """
    
    def __init__(self, registry: Optional[ModuleRegistry] = None):
        """
        Initialize the module importer.
        
        Args:
            registry: Module registry to use (creates new one if not provided)
        """
        self.registry = registry or ModuleRegistry()
        self._search_paths: List[str] = []
    
    def add_search_path(self, path: str) -> None:
        """
        Add a directory to search for modules.
        
        Args:
            path: Directory path to add
        """
        if os.path.isdir(path) and path not in self._search_paths:
            self._search_paths.append(path)
            logger.info(f"Added module search path: {path}")
    
    def load_module_from_file(self, file_path: str, config: Optional[Dict[str, Any]] = None) -> ModuleBase:
        """
        Load a module from a Python file.
        
        Args:
            file_path: Path to the Python file containing the module
            config: Optional configuration to pass to the module
            
        Returns:
            Loaded module instance
            
        Raises:
            ImportError: If module cannot be loaded
            ValueError: If module doesn't contain valid ModuleBase subclass
        """
        if not os.path.exists(file_path):
            raise ImportError(f"Module file not found: {file_path}")
        
        # Load the module
        module_name = Path(file_path).stem
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load module from {file_path}")
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        
        # Find ModuleBase subclass
        module_class = self._find_module_class(module)
        if module_class is None:
            raise ValueError(f"No ModuleBase subclass found in {file_path}")
        
        # Instantiate and initialize
        module_instance = module_class(config)
        if not module_instance.initialize():
            raise RuntimeError(f"Failed to initialize module from {file_path}")
        
        module_instance._initialized = True
        
        # Register the module
        self.registry.register(module_instance, file_path)
        
        logger.info(f"Loaded module '{module_instance.get_name()}' from {file_path}")
        return module_instance
    
    def load_module_from_directory(self, directory: str, config: Optional[Dict[str, Any]] = None) -> List[ModuleBase]:
        """
        Load all modules from a directory.
        
        Args:
            directory: Directory path to scan for modules
            config: Optional configuration to pass to modules
            
        Returns:
            List of loaded module instances
        """
        if not os.path.isdir(directory):
            raise ValueError(f"Directory not found: {directory}")
        
        loaded_modules = []
        for file_name in os.listdir(directory):
            # Load .py files
            if file_name.endswith('.py') and not file_name.startswith('_'):
                file_path = os.path.join(directory, file_name)
                try:
                    module = self.load_module_from_file(file_path, config)
                    loaded_modules.append(module)
                except Exception as e:
                    logger.error(f"Failed to load module from {file_path}: {e}")
            # Load .module container files
            elif file_name.endswith('.module'):
                file_path = os.path.join(directory, file_name)
                try:
                    module = self.load_module_from_container(file_path, config)
                    loaded_modules.append(module)
                except Exception as e:
                    logger.error(f"Failed to load module container from {file_path}: {e}")
        
        return loaded_modules
    
    def load_module_from_container(self, container_path: str, config: Optional[Dict[str, Any]] = None) -> ModuleBase:
        """
        Load a module from a .module container file.
        
        Args:
            container_path: Path to the .module container file
            config: Optional configuration to pass to the module
            
        Returns:
            Loaded module instance
            
        Raises:
            ImportError: If module cannot be loaded
            ValueError: If container or module is invalid
        """
        if not os.path.exists(container_path):
            raise ImportError(f"Module container not found: {container_path}")
        
        # Create and validate container
        container = ModuleContainer(container_path)
        
        # Merge container metadata with provided config
        merged_config = container.get_metadata().get('config', {})
        if config:
            merged_config.update(config)
        
        # Extract container to temporary directory
        extracted_path = container.extract()
        
        # Add extracted path to system path
        if extracted_path not in sys.path:
            sys.path.insert(0, extracted_path)
        
        try:
            # Load the module from __init__.py
            entry_point = container.get_entry_point()
            
            # Create unique module name based on container
            module_name = f"_container_{Path(container_path).stem}"
            spec = importlib.util.spec_from_file_location(module_name, entry_point)
            if spec is None or spec.loader is None:
                raise ImportError(f"Cannot load module from {entry_point}")
            
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            
            # Find ModuleBase subclass
            module_class = self._find_module_class(module)
            if module_class is None:
                raise ValueError(f"No ModuleBase subclass found in container {container_path}")
            
            # Instantiate and initialize
            module_instance = module_class(merged_config)
            if not module_instance.initialize():
                raise RuntimeError(f"Failed to initialize module from container {container_path}")
            
            module_instance._initialized = True
            
            # Register the module with container reference
            self.registry.register(module_instance, container_path, container)
            
            logger.info(f"Loaded module '{module_instance.get_name()}' from container {container_path}")
            return module_instance
            
        except Exception as e:
            # Clean up on error
            container.cleanup()
            if extracted_path in sys.path:
                sys.path.remove(extracted_path)
            raise
    
    def _find_module_class(self, module) -> Optional[Type[ModuleBase]]:
        """
        Find ModuleBase subclass in a loaded module.
        
        Args:
            module: Loaded Python module
            
        Returns:
            ModuleBase subclass or None if not found
        """
        for item_name in dir(module):
            item = getattr(module, item_name)
            if (isinstance(item, type) and 
                issubclass(item, ModuleBase) and 
                item is not ModuleBase):
                return item
        return None
    
    def unload_module(self, name: str) -> None:
        """
        Unload a module by name.
        
        Args:
            name: Name of the module to unload
        """
        self.registry.unregister(name)
    
    def get_module(self, name: str) -> Optional[ModuleBase]:
        """
        Get a loaded module by name.
        
        Args:
            name: Name of the module
            
        Returns:
            Module instance or None if not found
        """
        return self.registry.get(name)
    
    def execute_module(self, name: str, **kwargs) -> Dict[str, Any]:
        """
        Execute a module by name.
        
        Args:
            name: Name of the module to execute
            **kwargs: Arguments to pass to the module's execute method
            
        Returns:
            Execution results
            
        Raises:
            ValueError: If module not found or not enabled
        """
        module = self.registry.get(name)
        if module is None:
            raise ValueError(f"Module '{name}' not found")
        
        if not module.is_enabled():
            raise ValueError(f"Module '{name}' is not enabled")
        
        return module.execute(**kwargs)

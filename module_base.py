"""
Base module interface for the CMS module importing system.

All modules must inherit from this base class to ensure consistent structure.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List


class ModuleBase(ABC):
    """
    Base class for all CMS modules.
    
    All modules must implement the required abstract methods to be compatible
    with the module importing system.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the module with optional configuration.
        
        Args:
            config: Dictionary containing module-specific configuration
        """
        self.config = config or {}
        self._initialized = False
        self._enabled = True
    
    @abstractmethod
    def get_name(self) -> str:
        """
        Return the unique name of this module.
        
        Returns:
            String identifier for the module
        """
        pass
    
    @abstractmethod
    def get_version(self) -> str:
        """
        Return the version of this module.
        
        Returns:
            Version string (e.g., "1.0.0")
        """
        pass
    
    @abstractmethod
    def get_description(self) -> str:
        """
        Return a brief description of what this module does.
        
        Returns:
            Description string
        """
        pass
    
    @abstractmethod
    def initialize(self) -> bool:
        """
        Initialize the module. Called after module is loaded.
        
        Returns:
            True if initialization was successful, False otherwise
        """
        pass
    
    @abstractmethod
    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the main functionality of the module.
        
        Args:
            **kwargs: Arbitrary keyword arguments specific to the module
            
        Returns:
            Dictionary containing execution results
        """
        pass
    
    def shutdown(self) -> None:
        """
        Clean up resources when module is unloaded.
        Can be overridden by subclasses if needed.
        """
        self._initialized = False
    
    def get_dependencies(self) -> List[str]:
        """
        Return list of module names this module depends on.
        Can be overridden by subclasses.
        
        Returns:
            List of module names
        """
        return []
    
    def is_initialized(self) -> bool:
        """Check if module is initialized."""
        return self._initialized
    
    def is_enabled(self) -> bool:
        """Check if module is enabled."""
        return self._enabled
    
    def enable(self) -> None:
        """Enable the module."""
        self._enabled = True
    
    def disable(self) -> None:
        """Disable the module."""
        self._enabled = False
    
    def get_info(self) -> Dict[str, Any]:
        """
        Get comprehensive information about the module.
        
        Returns:
            Dictionary with module metadata
        """
        return {
            'name': self.get_name(),
            'version': self.get_version(),
            'description': self.get_description(),
            'initialized': self.is_initialized(),
            'enabled': self.is_enabled(),
            'dependencies': self.get_dependencies(),
            'config': self.config
        }

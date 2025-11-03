# Module Importer System Documentation

## Overview

The Module Importer System is a flexible, extensible framework for dynamically loading and managing modules in a CMS environment. It provides a unified interface for creating, loading, and executing modules with features like dependency management, configuration support, and module lifecycle management.

## Architecture

The system consists of four main components:

### 1. ModuleBase (module_base.py)
An abstract base class that defines the interface all modules must implement. It ensures consistent structure across all modules.

### 2. ModuleRegistry (module_importer.py)
A registry that manages loaded module instances, tracks their state, and provides access to registered modules.

### 3. ModuleImporter (module_importer.py)
The main loader that dynamically imports modules from files, directories, or containers and registers them with the registry.

### 4. ModuleContainer (module_container.py)
A container format (.module files) for packaging multi-file modules with dependencies, resources, and metadata.

## Creating a Module

All modules must inherit from `ModuleBase` and implement the required abstract methods:

```python
from module_base import ModuleBase
from typing import Dict, Any, List

class MyModule(ModuleBase):
    def get_name(self) -> str:
        """Return unique module identifier"""
        return "my_module"
    
    def get_version(self) -> str:
        """Return module version"""
        return "1.0.0"
    
    def get_description(self) -> str:
        """Return module description"""
        return "Description of what this module does"
    
    def initialize(self) -> bool:
        """Initialize module resources"""
        # Setup code here
        return True
    
    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute module's main functionality"""
        # Module logic here
        return {'success': True, 'result': 'data'}
    
    def get_dependencies(self) -> List[str]:
        """Return list of required module names (optional)"""
        return []
```

## Using the Module Importer

### Basic Usage

```python
from module_importer import ModuleImporter, ModuleRegistry

# Create importer
importer = ModuleImporter()

# Load a single module file
module = importer.load_module_from_file('path/to/module.py')

# Load a module from a container
module = importer.load_module_from_container('path/to/module.module')

# Load all modules from a directory (includes .py and .module files)
modules = importer.load_module_from_directory('modules/')

# Execute a module
results = importer.execute_module('module_name', param1='value1')

# Get a module instance
module = importer.get_module('module_name')

# Unload a module
importer.unload_module('module_name')
```

### Module Configuration

Pass configuration to modules during loading:

```python
config = {
    'api_key': 'your-api-key',
    'timeout': 30,
    'options': ['option1', 'option2']
}

module = importer.load_module_from_file('module.py', config=config)
```

Access configuration in your module:

```python
class MyModule(ModuleBase):
    def initialize(self) -> bool:
        self.api_key = self.config.get('api_key')
        self.timeout = self.config.get('timeout', 60)
        return True
```

### Module Registry

The registry provides methods to manage and query loaded modules:

```python
registry = importer.registry

# List all module names
module_names = registry.list_modules()

# Get module instance
module = registry.get('module_name')

# Get information about all modules
all_info = registry.get_all_info()

# Unregister a module
registry.unregister('module_name')

# Clear all modules
registry.clear()
```

## Module Containers

Module containers (.module files) allow you to package multi-file modules with all their dependencies, resources, and metadata.

### Container Format

A .module file is a ZIP archive with this structure:

```
module_name.module (ZIP file)
├── module.json           # Module metadata and configuration
├── __init__.py          # Main module entry point (required)
├── helper.py            # Additional Python files
├── utils.py             # More Python files
├── resources/           # Resources directory (optional)
│   ├── data.json
│   └── templates/
└── README.md            # Module documentation (optional)
```

### Creating a Module Container

#### Using the Utility Script

The easiest way to create a container:

```bash
python create_module_package.py my_module_dir my_module \
  --version 2.0.0 \
  --description "My awesome module" \
  --author "Your Name" \
  --dependencies "auth_module,database_module"
```

#### Programmatically

```python
from module_container import ModuleContainer

metadata = {
    'name': 'my_module',
    'version': '1.0.0',
    'description': 'Module description',
    'author': 'Your Name',
    'dependencies': ['other_module'],
    'config': {'default_option': 'value'}
}

container_path = ModuleContainer.create_container(
    'path/to/module_directory',
    'output/my_module.module',
    metadata
)
```

### Loading from Containers

```python
# Load a single container
module = importer.load_module_from_container('my_module.module')

# Load all modules from directory (includes .module files)
modules = importer.load_module_from_directory('modules/')
```

### Container Metadata (module.json)

The module.json file contains module metadata:

```json
{
  "name": "my_module",
  "version": "1.0.0",
  "description": "Module description",
  "author": "Your Name",
  "dependencies": ["dep1", "dep2"],
  "config": {
    "default_setting": "value"
  }
}
```

### Multi-File Module Structure

When creating a multi-file module, organize it like a Python package:

```
my_advanced_module/
├── __init__.py          # Main module class (inherits ModuleBase)
├── engine.py            # Supporting module
├── utils.py             # Utility functions
├── resources/
│   └── data.json        # Resource files
└── README.md
```

**__init__.py example:**

```python
from module_base import ModuleBase
from .engine import Engine
from .utils import helper_function

class MyAdvancedModule(ModuleBase):
    def get_name(self):
        return "my_advanced_module"
    
    def initialize(self):
        self.engine = Engine(self.config)
        return True
    
    def execute(self, **kwargs):
        result = self.engine.process(helper_function(kwargs))
        return {'success': True, 'result': result}
```

### Container Benefits

1. **Package Multiple Files**: Include helper modules, utilities, and resources
2. **Metadata Management**: Store version, dependencies, and configuration
3. **Easy Distribution**: Single file contains everything
4. **Automatic Cleanup**: Temporary files cleaned up when module unloaded
5. **Isolation**: Each container extracts to its own temporary directory

## Module Lifecycle

1. **Loading**: Module file is imported, and the ModuleBase subclass is instantiated
2. **Initialization**: `initialize()` method is called to set up resources
3. **Registration**: Module is registered in the ModuleRegistry
4. **Execution**: `execute()` method can be called multiple times
5. **Shutdown**: `shutdown()` method is called when module is unloaded

## Module Features

### Enable/Disable

```python
module = importer.get_module('module_name')
module.disable()  # Disable the module
module.enable()   # Re-enable the module

if module.is_enabled():
    results = module.execute()
```

### Module Information

```python
module = importer.get_module('module_name')
info = module.get_info()

# Returns:
# {
#     'name': 'module_name',
#     'version': '1.0.0',
#     'description': 'Module description',
#     'initialized': True,
#     'enabled': True,
#     'dependencies': [],
#     'config': {}
# }
```

### Dependencies

Declare dependencies in your module:

```python
def get_dependencies(self) -> List[str]:
    return ['database_module', 'auth_module']
```

## Example Modules

### Code Scanner Module (Single File)

The `code_scanner` module scans repository code for security issues and code quality problems.

```python
results = importer.execute_module(
    'code_scanner',
    path='/path/to/scan',
    recursive=True
)

# Returns scan results with issues found
for issue in results['issues_found']:
    print(f"{issue['file']}:{issue['line']} - {issue['issue_type']}")
```

### Repository Metadata Module (Single File)

The `repo_metadata` module analyzes repository structure and extracts metadata.

```python
results = importer.execute_module(
    'repo_metadata',
    path='/path/to/repo',
    recursive=True
)

# Returns metadata about the repository
print(f"Total files: {results['total_files']}")
print(f"Languages: {results['languages']}")
```

### Advanced Scanner Module (Multi-File Container)

The `advanced_scanner` module demonstrates a multi-file module packaged as a container.

```python
# Load from container
module = importer.load_module_from_container('advanced_scanner.module')

# Execute with multiple scan types
results = importer.execute_module(
    'advanced_scanner',
    path='/path/to/scan',
    scan_types=['security', 'quality', 'complexity'],
    output_format='text'
)

print(results['report'])
```

This module includes:
- `__init__.py`: Main module interface
- `scanner_engine.py`: Scanning logic with multiple scan types
- `report_generator.py`: Report generation in multiple formats
- `resources/`: Resource files and templates

## Best Practices

1. **Module Naming**: Use unique, descriptive names for modules
2. **Error Handling**: Always handle exceptions in `execute()` and return meaningful error messages
3. **Configuration**: Make modules configurable rather than hardcoding values
4. **Logging**: Use Python's logging module for diagnostic output
5. **Resource Cleanup**: Implement `shutdown()` if your module uses external resources
6. **Dependencies**: Declare all module dependencies explicitly
7. **Return Format**: Always return a dictionary from `execute()` with a 'success' key
8. **Versioning**: Use semantic versioning (major.minor.patch)

## Module Directory Structure

```
project/
├── module_base.py              # Base module interface
├── module_importer.py          # Importer and registry
├── example_usage.py            # Usage examples
├── modules/                    # Module directory
│   ├── code_scanner.py        # Code scanning module
│   ├── repo_metadata.py       # Repository metadata module
│   └── custom_module.py       # Your custom modules
└── README.md                   # This documentation
```

## Advanced Usage

### Custom Module Search Paths

```python
importer = ModuleImporter()
importer.add_search_path('/path/to/modules1')
importer.add_search_path('/path/to/modules2')
```

### Module Execution with Error Handling

```python
try:
    results = importer.execute_module('module_name', param='value')
    if results.get('success'):
        print("Module executed successfully")
    else:
        print(f"Module execution failed: {results.get('error')}")
except ValueError as e:
    print(f"Module not found or not enabled: {e}")
```

### Loading Modules with Validation

```python
try:
    module = importer.load_module_from_file('module.py')
    assert module.is_initialized(), "Module not initialized"
    assert module.is_enabled(), "Module not enabled"
except (ImportError, ValueError, AssertionError) as e:
    print(f"Failed to load module: {e}")
```

## Logging

The system uses Python's logging module. Configure logging in your application:

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

## Troubleshooting

### Module Not Found
- Check that the file path is correct
- Ensure the file contains a class that inherits from ModuleBase
- Verify the module file is valid Python code

### Module Already Registered
- Use `importer.unload_module(name)` before loading again
- Check for duplicate module names

### Module Initialization Failed
- Check the module's `initialize()` method for errors
- Review module configuration requirements
- Check module dependencies are available

## Contributing New Modules

To contribute a new module:

1. Create a new Python file in the `modules/` directory
2. Inherit from `ModuleBase`
3. Implement all required abstract methods
4. Test your module with the example_usage.py script
5. Document your module's functionality and parameters

## API Reference

### ModuleBase

**Methods:**
- `get_name() -> str`: Return module name
- `get_version() -> str`: Return module version
- `get_description() -> str`: Return module description
- `initialize() -> bool`: Initialize module
- `execute(**kwargs) -> Dict[str, Any]`: Execute module
- `shutdown() -> None`: Clean up resources
- `get_dependencies() -> List[str]`: Return dependencies
- `is_initialized() -> bool`: Check initialization status
- `is_enabled() -> bool`: Check enabled status
- `enable() -> None`: Enable module
- `disable() -> None`: Disable module
- `get_info() -> Dict[str, Any]`: Get module information

### ModuleImporter

**Methods:**
- `load_module_from_file(file_path, config=None) -> ModuleBase`
- `load_module_from_directory(directory, config=None) -> List[ModuleBase]`
- `unload_module(name) -> None`
- `get_module(name) -> Optional[ModuleBase]`
- `execute_module(name, **kwargs) -> Dict[str, Any]`
- `add_search_path(path) -> None`

### ModuleRegistry

**Methods:**
- `register(module, source_path=None) -> None`
- `unregister(name) -> None`
- `get(name) -> Optional[ModuleBase]`
- `list_modules() -> List[str]`
- `get_all_info() -> List[Dict[str, Any]]`
- `clear() -> None`

# Module Importer System

A flexible, extensible framework for dynamically loading and managing modules in a CMS environment. This system provides a unified module design for importing repo code scanning modules and other plugin-style components.

## Features

- **Unified Module Interface**: All modules implement a consistent base class with standard lifecycle methods
- **Dynamic Loading**: Load modules from files, directories, or containers at runtime
- **Module Containers**: Package multi-file modules with dependencies and resources in .module files
- **Module Registry**: Track and manage all loaded modules
- **Configuration Support**: Pass configuration to modules during loading
- **Dependency Management**: Modules can declare dependencies on other modules
- **Lifecycle Management**: Initialize, execute, and shutdown modules cleanly
- **Enable/Disable**: Control module execution without unloading
- **Extensible**: Easy to create new modules by extending the base class

## Quick Start

### Installation

No external dependencies required - uses only Python standard library.

```bash
git clone https://github.com/J-Ellette/module_importer.git
cd module_importer
```

### Basic Usage

```python
from module_importer import ModuleImporter

# Create importer and load modules
importer = ModuleImporter()

# Load from .py files
modules = importer.load_module_from_directory('modules/')

# Load from .module container
module = importer.load_module_from_container('advanced_scanner.module')

# Execute a module
results = importer.execute_module('code_scanner', path='.', recursive=True)
print(f"Scanned {results['summary']['total_files']} files")
```

### Creating Module Containers

```bash
# Package a multi-file module
python create_module_package.py my_module_dir my_module \
  --version 1.0.0 \
  --description "My module"
```

### Run Examples

```bash
# Basic module loading
python example_usage.py

# Module container examples
python example_container_usage.py
```

## Project Structure

```
module_importer/
├── module_base.py                    # Base module interface (abstract class)
├── module_importer.py                # Module importer and registry
├── module_container.py               # Module container format support
├── create_module_package.py          # Utility to create .module files
├── example_usage.py                  # Basic usage examples
├── example_container_usage.py        # Container usage examples
├── test_module_system.py             # Comprehensive test suite
├── MODULE_DOCUMENTATION.md           # Detailed documentation
├── modules/                          # Single-file modules
│   ├── code_scanner.py              # Code scanning module
│   └── repo_metadata.py             # Repository metadata module
├── example_advanced_scanner/         # Multi-file module example
│   ├── __init__.py                  # Module entry point
│   ├── scanner_engine.py            # Scanning engine
│   └── report_generator.py          # Report generator
├── advanced_scanner.module           # Packaged container
└── README.md                         # This file
```

## Included Modules

### Code Scanner Module (Single File)
Scans repository code for security issues, bugs, and quality concerns:
- Hardcoded passwords and API keys
- SQL injection patterns
- Debug mode issues
- Custom pattern matching

### Repository Metadata Module (Single File)
Analyzes repository structure and extracts metadata:
- File types and counts
- Language detection and distribution
- Configuration files
- Directory structure analysis

### Advanced Scanner Module (Multi-File Container)
Demonstrates a complex module with multiple components:
- Multiple scan types (security, quality, complexity)
- Multiple report formats (JSON, text, summary)
- Modular architecture with separate engine and reporter
- Packaged as a .module container file

## Creating Your Own Module

```python
from module_base import ModuleBase
from typing import Dict, Any

class MyModule(ModuleBase):
    def get_name(self) -> str:
        return "my_module"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def get_description(self) -> str:
        return "My custom module"
    
    def initialize(self) -> bool:
        # Setup code
        return True
    
    def execute(self, **kwargs) -> Dict[str, Any]:
        # Module logic
        return {'success': True}
```

## Documentation

For complete documentation, see [MODULE_DOCUMENTATION.md](MODULE_DOCUMENTATION.md)

Topics covered:
- Architecture overview
- Creating modules
- Module lifecycle
- Configuration
- Dependencies
- API reference
- Best practices
- Troubleshooting

## Use Cases

- **CMS Plugin System**: Load content modules, widgets, or extensions
- **Code Analysis**: Scan repositories for security, quality, or compliance issues
- **Build Pipeline**: Dynamically load build steps or validators
- **Testing Framework**: Load test modules or custom assertions
- **Data Processing**: Chain data transformation modules
- **Monitoring**: Load metric collectors or alerting modules

## Requirements

- Python 3.6+
- No external dependencies

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! To add a new module:

1. Create a new file in `modules/` directory
2. Inherit from `ModuleBase`
3. Implement all required methods
4. Test with `example_usage.py`
5. Submit a pull request

## Support

For issues, questions, or contributions, please open an issue on GitHub.
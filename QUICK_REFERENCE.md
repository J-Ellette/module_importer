# Quick Reference Guide

## Module Importer System Quick Reference

### Creating a Simple Module

```python
from module_base import ModuleBase

class MyModule(ModuleBase):
    def get_name(self): return "my_module"
    def get_version(self): return "1.0.0"
    def get_description(self): return "My module description"
    def initialize(self): return True
    def execute(self, **kwargs):
        return {'success': True, 'result': 'Hello World'}
```

### Loading and Executing Modules

```python
from module_importer import ModuleImporter

# Create importer
importer = ModuleImporter()

# Load single file
module = importer.load_module_from_file('my_module.py')

# Load from container
module = importer.load_module_from_container('my_module.module')

# Load all from directory
modules = importer.load_module_from_directory('modules/')

# Execute
results = importer.execute_module('my_module', param='value')
```

### Creating a Module Container

```bash
# Structure your multi-file module
my_module/
  __init__.py     # Must have this with ModuleBase subclass
  helper.py
  utils.py

# Package it
python create_module_package.py my_module my_module --version 1.0.0
```

### Module Container Structure

```
my_module.module (ZIP)
  ├── module.json      # Metadata
  ├── __init__.py      # Entry point (required)
  └── other files...   # Additional files
```

### Common Operations

```python
# Get module info
module = importer.get_module('module_name')
info = module.get_info()

# Enable/disable
module.disable()
module.enable()

# List all modules
names = importer.registry.list_modules()

# Unload module
importer.unload_module('module_name')
```

### Configuration

```python
config = {
    'setting1': 'value1',
    'setting2': 42
}

# Pass to single module
module = importer.load_module_from_file('module.py', config)

# Access in module
class MyModule(ModuleBase):
    def initialize(self):
        self.setting1 = self.config.get('setting1')
        return True
```

### Best Practices

1. **Single File Modules**: Use for simple, self-contained functionality
2. **Container Modules**: Use for complex modules with multiple files
3. **Error Handling**: Always return `{'success': bool, ...}` from execute()
4. **Dependencies**: Declare in `get_dependencies()` method
5. **Resource Cleanup**: Implement `shutdown()` if needed
6. **Versioning**: Use semantic versioning (major.minor.patch)

### Example Scan Result

```python
results = importer.execute_module('code_scanner', path='.')

# Typical result structure:
{
    'success': True,
    'summary': {
        'total_files': 10,
        'files_with_issues': 2,
        'total_issues': 5
    },
    'issues_found': [
        {
            'file': 'app.py',
            'line': 42,
            'issue_type': 'hardcoded_password',
            'severity': 'critical'
        }
    ]
}
```

### Testing Your Module

```python
import unittest
from module_importer import ModuleImporter

class TestMyModule(unittest.TestCase):
    def setUp(self):
        self.importer = ModuleImporter()
        
    def test_load_module(self):
        module = self.importer.load_module_from_file('my_module.py')
        self.assertIsNotNone(module)
        
    def test_execute(self):
        self.importer.load_module_from_file('my_module.py')
        results = self.importer.execute_module('my_module')
        self.assertTrue(results['success'])
```

### Troubleshooting

**Module not loading?**
- Check __init__.py exists in container
- Verify class inherits from ModuleBase
- Check initialize() returns True

**Import errors?**
- Ensure parent directory is in Python path
- Check relative imports use `from .module import`
- Verify all dependencies are available

**Container issues?**
- Verify .module file is valid ZIP
- Check module.json is valid JSON
- Ensure __init__.py has ModuleBase subclass

For complete documentation, see MODULE_DOCUMENTATION.md

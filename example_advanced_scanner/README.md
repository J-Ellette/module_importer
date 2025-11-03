# Advanced Scanner Module

This is an example of a multi-file module that demonstrates the module container system.

## Components

- **__init__.py**: Main module entry point and interface
- **scanner_engine.py**: Core scanning functionality with multiple scan types
- **report_generator.py**: Report generation in multiple formats

## Features

- Multiple scan types: security, quality, complexity
- Multiple report formats: JSON, text, summary
- Configurable scanning options

## Usage

```python
importer = ModuleImporter()
module = importer.load_module_from_container('advanced_scanner.module')

results = importer.execute_module(
    'advanced_scanner',
    path='/path/to/scan',
    scan_types=['security', 'quality'],
    output_format='text'
)
```

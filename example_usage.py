"""
Example usage of the module importing system.

This script demonstrates how to use the module importer to load and execute modules.
"""

import logging
import json
from module_importer import ModuleImporter, ModuleRegistry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def main():
    """Main example function."""
    print("=" * 60)
    print("Module Importer System - Example Usage")
    print("=" * 60)
    print()
    
    # Create importer with registry
    registry = ModuleRegistry()
    importer = ModuleImporter(registry)
    
    # Example 1: Load a specific module
    print("1. Loading code scanner module...")
    try:
        code_scanner = importer.load_module_from_file(
            'modules/code_scanner.py',
            config={'file_extensions': ['.py', '.js', '.ts']}
        )
        print(f"   ✓ Loaded: {code_scanner.get_name()} v{code_scanner.get_version()}")
        print(f"   Description: {code_scanner.get_description()}")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    print()
    
    # Example 2: Load all modules from a directory
    print("2. Loading all modules from 'modules' directory...")
    try:
        modules = importer.load_module_from_directory('modules')
        print(f"   ✓ Loaded {len(modules)} modules:")
        for module in modules:
            print(f"     - {module.get_name()} v{module.get_version()}")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    print()
    
    # Example 3: List all registered modules
    print("3. Listing all registered modules...")
    module_names = registry.list_modules()
    print(f"   Total modules: {len(module_names)}")
    for name in module_names:
        print(f"   - {name}")
    print()
    
    # Example 4: Get detailed information about modules
    print("4. Getting detailed module information...")
    all_info = registry.get_all_info()
    for info in all_info:
        print(f"   Module: {info['name']}")
        print(f"   Version: {info['version']}")
        print(f"   Status: {'Enabled' if info['enabled'] else 'Disabled'}")
        print(f"   Initialized: {info['initialized']}")
        print()
    
    # Example 5: Execute the code scanner module
    print("5. Executing code scanner module on current directory...")
    try:
        results = importer.execute_module(
            'code_scanner',
            path='.',
            recursive=True
        )
        
        if results.get('success'):
            summary = results['summary']
            print(f"   ✓ Scan completed successfully")
            print(f"   Files scanned: {summary['total_files']}")
            print(f"   Files with issues: {summary['files_with_issues']}")
            print(f"   Total issues: {summary['total_issues']}")
            
            if results['issues_found']:
                print("\n   Issues found:")
                for issue in results['issues_found'][:5]:  # Show first 5
                    print(f"     - {issue['file']}:{issue['line']} - {issue['issue_type']} (severity: {issue['severity']})")
                
                if len(results['issues_found']) > 5:
                    print(f"     ... and {len(results['issues_found']) - 5} more issues")
        else:
            print(f"   ✗ Scan failed: {results.get('error')}")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    print()
    
    # Example 6: Execute the repo metadata module
    print("6. Executing repo metadata module...")
    try:
        results = importer.execute_module(
            'repo_metadata',
            path='.',
            recursive=True
        )
        
        if results.get('success'):
            print(f"   ✓ Analysis completed successfully")
            print(f"   Total files: {results['total_files']}")
            print(f"   Total directories: {results['total_directories']}")
            
            if results['languages']:
                print("\n   Languages detected:")
                for lang, data in results['languages'].items():
                    print(f"     - {lang}: {data['count']} files ({data['percentage']}%)")
            
            if results['config_files']:
                print("\n   Configuration files found:")
                for config_file in results['config_files']:
                    print(f"     - {config_file}")
        else:
            print(f"   ✗ Analysis failed: {results.get('error')}")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    print()
    
    # Example 7: Disable and re-enable a module
    print("7. Demonstrating module enable/disable...")
    module = registry.get('code_scanner')
    if module:
        print(f"   Module enabled: {module.is_enabled()}")
        module.disable()
        print(f"   After disable: {module.is_enabled()}")
        module.enable()
        print(f"   After re-enable: {module.is_enabled()}")
    print()
    
    # Example 8: Unload a specific module
    print("8. Unloading a module...")
    importer.unload_module('code_scanner')
    print(f"   ✓ Unloaded code_scanner")
    print(f"   Remaining modules: {registry.list_modules()}")
    print()
    
    print("=" * 60)
    print("Example completed!")
    print("=" * 60)


if __name__ == '__main__':
    main()

"""
Example usage of module containers.

This script demonstrates loading modules from .module container files.
"""

import logging
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
    print("Module Container System - Example Usage")
    print("=" * 60)
    print()
    
    # Create importer with registry
    registry = ModuleRegistry()
    importer = ModuleImporter(registry)
    
    # Example 1: Load a module from a container file
    print("1. Loading advanced scanner from .module container...")
    try:
        scanner = importer.load_module_from_container('advanced_scanner.module')
        print(f"   ✓ Loaded: {scanner.get_name()} v{scanner.get_version()}")
        print(f"   Description: {scanner.get_description()}")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    print()
    
    # Example 2: Load all modules from directory (including containers)
    print("2. Loading all modules from 'modules' directory...")
    print("   (This loads both .py files and .module containers)")
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
        module = registry.get(name)
        print(f"   - {name} v{module.get_version()}")
    print()
    
    # Example 4: Execute the advanced scanner module
    print("4. Executing advanced scanner module...")
    try:
        results = importer.execute_module(
            'advanced_scanner',
            path='.',
            scan_types=['security', 'quality'],
            output_format='summary'
        )
        
        if results.get('success'):
            summary = results['summary']
            print(f"   ✓ Scan completed successfully")
            print(f"   Scans run: {summary['scans_run']}")
            print(f"   Total issues: {summary['total_issues']}")
            print(f"   Critical issues: {summary['critical_issues']}")
            
            print("\n   Report:")
            print("   " + results['report'].replace("\n", "\n   "))
        else:
            print(f"   ✗ Scan failed")
    except Exception as e:
        print(f"   ✗ Error: {e}")
        import traceback
        traceback.print_exc()
    print()
    
    # Example 5: Execute with different output format
    print("5. Executing with text report format...")
    try:
        results = importer.execute_module(
            'advanced_scanner',
            path='modules',
            scan_types=['security'],
            output_format='text'
        )
        
        if results.get('success'):
            print(f"   ✓ Scan completed")
            print("\n   First 500 characters of report:")
            report_preview = results['report'][:500]
            print("   " + report_preview.replace("\n", "\n   "))
            if len(results['report']) > 500:
                print("   ...")
    except Exception as e:
        print(f"   ✗ Error: {e}")
    print()
    
    # Example 6: Get detailed info about a container-based module
    print("6. Getting detailed info about container-based module...")
    module = registry.get('advanced_scanner')
    if module:
        info = module.get_info()
        print(f"   Name: {info['name']}")
        print(f"   Version: {info['version']}")
        print(f"   Description: {info['description']}")
        print(f"   Initialized: {info['initialized']}")
        print(f"   Enabled: {info['enabled']}")
    print()
    
    # Cleanup
    print("7. Cleaning up...")
    registry.clear()
    print("   ✓ All modules unloaded and cleaned up")
    print()
    
    print("=" * 60)
    print("Example completed!")
    print("=" * 60)


if __name__ == '__main__':
    main()

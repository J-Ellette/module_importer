#!/usr/bin/env python
"""
Example script demonstrating how to use the converted scanner modules.
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from module_importer import ModuleImporter


def main():
    """Demonstrate loading and using converted scanner modules."""
    
    print("=" * 70)
    print("Scanner Module Example")
    print("=" * 70)
    print()
    
    # Create importer
    importer = ModuleImporter()
    
    # Load a scanner module from .module container
    print("Loading security_scanner module...")
    try:
        module = importer.load_module_from_container('modules/security_scanner.module')
        print(f"✓ Loaded {module.get_name()} v{module.get_version()}")
        print(f"  Description: {module.get_description()}")
        print()
    except Exception as e:
        print(f"✗ Failed to load: {e}")
        return 1
    
    # Execute the scanner
    print("Executing security scanner on current directory...")
    try:
        results = importer.execute_module('security_scanner', path='.')
        
        if results.get('success'):
            print("✓ Scan completed successfully")
            print(f"  Target: {results.get('target_path')}")
            print(f"  Score: {results.get('score', 0):.1f}%")
            print(f"  Grade: {results.get('grade', 'N/A')}")
            print()
            
            # Print analysis summary if available
            if 'analysis' in results:
                analysis = results['analysis']
                if isinstance(analysis, dict):
                    print("Analysis:")
                    if 'strengths' in analysis:
                        print(f"  Strengths: {len(analysis.get('strengths', []))}")
                    if 'weaknesses' in analysis:
                        print(f"  Weaknesses: {len(analysis.get('weaknesses', []))}")
                    if 'recommendations' in analysis:
                        print(f"  Recommendations: {len(analysis.get('recommendations', []))}")
        else:
            print(f"✗ Scan failed: {results.get('error')}")
    except Exception as e:
        print(f"✗ Execution failed: {e}")
        return 1
    
    print()
    print("=" * 70)
    print("Loading Multiple Scanner Modules from Directory")
    print("=" * 70)
    print()
    
    # Load all modules from modules directory
    print("Loading all modules from modules/ directory...")
    modules = importer.load_module_from_directory('modules/')
    
    print(f"✓ Loaded {len(modules)} modules:")
    for mod in modules:
        info = mod.get_info()
        print(f"  - {info['name']} v{info['version']}")
    
    print()
    print("=" * 70)
    print("Available Scanner Modules")
    print("=" * 70)
    print()
    
    # List all available modules
    all_modules = importer.registry.list_modules()
    print(f"Total registered modules: {len(all_modules)}")
    
    # Filter scanner modules
    scanner_modules = [m for m in all_modules if 'scanner' in m.lower()]
    print(f"Scanner modules: {len(scanner_modules)}")
    for mod_name in sorted(scanner_modules)[:10]:  # Show first 10
        print(f"  - {mod_name}")
    
    if len(scanner_modules) > 10:
        print(f"  ... and {len(scanner_modules) - 10} more")
    
    print()
    print("✓ Example completed successfully!")
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python
"""
Script to convert all scanner modules from modules_to_convert/modules/ 
to .module container files in the modules/ directory.
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from module_container import ModuleContainer


def convert_module(source_dir: str, module_name: str, output_dir: str, common_dir: str) -> bool:
    """
    Convert a single module directory to a .module file.
    
    Args:
        source_dir: Source module directory path
        module_name: Name of the module
        output_dir: Output directory for .module file
        common_dir: Path to common utilities directory
        
    Returns:
        True if successful, False otherwise
    """
    # Check if __init__.py exists
    init_file = os.path.join(source_dir, '__init__.py')
    if not os.path.exists(init_file):
        print(f"  ⊗ Skipping {module_name}: No __init__.py found")
        return False
    
    # Create metadata
    metadata = {
        'name': module_name,
        'version': '1.0.0',
        'description': f'{module_name.replace("_", " ").title()} Module',
        'author': 'CIV-ARCOS',
        'dependencies': [],
        'config': {}
    }
    
    # Create output path
    output_path = os.path.join(output_dir, f'{module_name}.module')
    
    # Create temporary directory to combine module and common files
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Copy module files to temp directory
        for item in os.listdir(source_dir):
            src_path = os.path.join(source_dir, item)
            dst_path = os.path.join(temp_dir, item)
            if os.path.isdir(src_path):
                shutil.copytree(src_path, dst_path)
            else:
                shutil.copy2(src_path, dst_path)
        
        # Copy common directory to temp directory
        common_dst = os.path.join(temp_dir, 'common')
        shutil.copytree(common_dir, common_dst)
        
        # Create the container from the temp directory
        container_path = ModuleContainer.create_container(
            temp_dir,
            output_path,
            metadata
        )
        
        print(f"  ✓ Created {module_name}.module")
        return True
        
    except Exception as e:
        print(f"  ✗ Failed to create {module_name}.module: {e}")
        return False
    finally:
        # Clean up temp directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


def main():
    """Main conversion function."""
    # Define paths
    repo_root = os.path.dirname(os.path.abspath(__file__))
    source_base = os.path.join(repo_root, 'modules_to_convert', 'modules')
    output_dir = os.path.join(repo_root, 'modules')
    common_dir = os.path.join(source_base, 'common')
    
    # Modules to skip
    skip_modules = {'common', 'headless_PowerShield', 'headless_drakon'}
    
    print("=" * 70)
    print("Converting Scanner Modules to .module Containers")
    print("=" * 70)
    print(f"Source: {source_base}")
    print(f"Output: {output_dir}")
    print(f"Common: {common_dir}")
    print()
    
    # Get all module directories
    if not os.path.exists(source_base):
        print(f"Error: Source directory not found: {source_base}")
        sys.exit(1)
    
    if not os.path.exists(common_dir):
        print(f"Error: Common directory not found: {common_dir}")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Find all module directories
    module_dirs = []
    for item in sorted(os.listdir(source_base)):
        item_path = os.path.join(source_base, item)
        if os.path.isdir(item_path) and item not in skip_modules:
            module_dirs.append((item, item_path))
    
    print(f"Found {len(module_dirs)} modules to convert")
    print()
    
    # Convert each module
    successful = 0
    failed = 0
    skipped = 0
    
    for module_name, module_path in module_dirs:
        result = convert_module(module_path, module_name, output_dir, common_dir)
        if result:
            successful += 1
        elif result is False:
            if not os.path.exists(os.path.join(module_path, '__init__.py')):
                skipped += 1
            else:
                failed += 1
    
    # Print summary
    print()
    print("=" * 70)
    print("Conversion Summary")
    print("=" * 70)
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Skipped: {skipped}")
    print(f"Total: {len(module_dirs)}")
    print()
    
    if failed > 0:
        print("Some modules failed to convert. Check the output above for details.")
        sys.exit(1)
    else:
        print("✓ All modules converted successfully!")


if __name__ == '__main__':
    main()

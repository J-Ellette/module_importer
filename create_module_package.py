#!/usr/bin/env python
"""
Utility script to create .module container files.

Usage:
    python create_module_package.py <source_directory> <output_name> [options]
    
Example:
    python create_module_package.py my_module my_module --version 1.0.0
"""

import argparse
import sys
import os
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from module_container import ModuleContainer


def create_metadata(args) -> dict:
    """
    Create metadata dictionary from command line arguments.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        Metadata dictionary
    """
    metadata = {
        'name': args.name or Path(args.source).name,
        'version': args.version or '1.0.0',
        'description': args.description or '',
        'author': args.author or '',
        'config': {}
    }
    
    if args.dependencies:
        metadata['dependencies'] = args.dependencies.split(',')
    
    if args.config:
        # Parse config as JSON
        try:
            metadata['config'] = json.loads(args.config)
        except json.JSONDecodeError:
            print(f"Warning: Invalid JSON in config, ignoring: {args.config}")
    
    return metadata


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description='Create a .module container file from a module directory',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create a simple module container
  python create_module_package.py my_module my_module
  
  # Create with metadata
  python create_module_package.py my_module my_module \\
    --version 2.0.0 \\
    --description "My awesome module" \\
    --author "Your Name"
  
  # Create with dependencies
  python create_module_package.py my_module my_module \\
    --dependencies "auth_module,database_module"
        """
    )
    
    parser.add_argument(
        'source',
        help='Source directory containing module files (must have __init__.py)'
    )
    
    parser.add_argument(
        'output',
        help='Output name for the .module file (without extension)'
    )
    
    parser.add_argument(
        '--name',
        help='Module name (defaults to directory name)'
    )
    
    parser.add_argument(
        '--version',
        default='1.0.0',
        help='Module version (default: 1.0.0)'
    )
    
    parser.add_argument(
        '--description',
        default='',
        help='Module description'
    )
    
    parser.add_argument(
        '--author',
        default='',
        help='Module author'
    )
    
    parser.add_argument(
        '--dependencies',
        help='Comma-separated list of module dependencies'
    )
    
    parser.add_argument(
        '--config',
        help='Default configuration as JSON string'
    )
    
    parser.add_argument(
        '--output-dir',
        default='.',
        help='Output directory (default: current directory)'
    )
    
    args = parser.parse_args()
    
    # Validate source directory
    if not os.path.isdir(args.source):
        print(f"Error: Source directory not found: {args.source}")
        sys.exit(1)
    
    init_file = os.path.join(args.source, '__init__.py')
    if not os.path.exists(init_file):
        print(f"Error: __init__.py not found in {args.source}")
        print("All modules must have an __init__.py file as the entry point.")
        sys.exit(1)
    
    # Create output path
    output_path = os.path.join(args.output_dir, args.output)
    if not output_path.endswith('.module'):
        output_path += '.module'
    
    # Create metadata
    metadata = create_metadata(args)
    
    # Display information
    print("=" * 60)
    print("Creating Module Container")
    print("=" * 60)
    print(f"Source directory: {args.source}")
    print(f"Output file: {output_path}")
    print(f"Module name: {metadata['name']}")
    print(f"Version: {metadata['version']}")
    if metadata['description']:
        print(f"Description: {metadata['description']}")
    if metadata.get('dependencies'):
        print(f"Dependencies: {', '.join(metadata['dependencies'])}")
    print()
    
    # Create the container
    try:
        container_path = ModuleContainer.create_container(
            args.source,
            output_path,
            metadata
        )
        
        print(f"✓ Successfully created module container: {container_path}")
        
        # Display container contents
        with ModuleContainer(container_path) as container:
            files = container.list_files()
            print(f"\nContainer contains {len(files)} files:")
            for file in sorted(files):
                print(f"  - {file}")
        
        print("\nYou can now load this module using:")
        print(f"  importer.load_module_from_container('{os.path.basename(container_path)}')")
        
    except Exception as e:
        print(f"✗ Error creating module container: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

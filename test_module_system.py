"""
Tests for the module importing system.

Run with: python -m pytest test_module_system.py
or: python test_module_system.py
"""

import unittest
import os
import sys
from pathlib import Path
import tempfile
import shutil

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from module_base import ModuleBase
from module_importer import ModuleImporter, ModuleRegistry
from module_container import ModuleContainer


class TestModule(ModuleBase):
    """Simple test module for testing."""
    
    def get_name(self) -> str:
        return "test_module"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def get_description(self) -> str:
        return "Test module"
    
    def initialize(self) -> bool:
        return True
    
    def execute(self, **kwargs):
        return {'success': True, 'message': 'Test executed', 'kwargs': kwargs}


class TestModuleBase(unittest.TestCase):
    """Test ModuleBase functionality."""
    
    def test_module_creation(self):
        """Test creating a module instance."""
        module = TestModule()
        self.assertEqual(module.get_name(), "test_module")
        self.assertEqual(module.get_version(), "1.0.0")
        self.assertIsInstance(module.get_description(), str)
    
    def test_module_initialization(self):
        """Test module initialization."""
        module = TestModule()
        self.assertTrue(module.initialize())
    
    def test_module_enable_disable(self):
        """Test enabling and disabling modules."""
        module = TestModule()
        self.assertTrue(module.is_enabled())
        
        module.disable()
        self.assertFalse(module.is_enabled())
        
        module.enable()
        self.assertTrue(module.is_enabled())
    
    def test_module_config(self):
        """Test module configuration."""
        config = {'key1': 'value1', 'key2': 42}
        module = TestModule(config=config)
        self.assertEqual(module.config, config)
    
    def test_module_info(self):
        """Test getting module information."""
        module = TestModule()
        module.initialize()
        module._initialized = True
        
        info = module.get_info()
        self.assertEqual(info['name'], 'test_module')
        self.assertEqual(info['version'], '1.0.0')
        self.assertTrue(info['enabled'])


class TestModuleRegistry(unittest.TestCase):
    """Test ModuleRegistry functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.registry = ModuleRegistry()
    
    def test_register_module(self):
        """Test registering a module."""
        module = TestModule()
        self.registry.register(module)
        self.assertIn('test_module', self.registry.list_modules())
    
    def test_register_duplicate_module(self):
        """Test registering duplicate module raises error."""
        module1 = TestModule()
        module2 = TestModule()
        
        self.registry.register(module1)
        with self.assertRaises(ValueError):
            self.registry.register(module2)
    
    def test_get_module(self):
        """Test getting a module from registry."""
        module = TestModule()
        self.registry.register(module)
        
        retrieved = self.registry.get('test_module')
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.get_name(), 'test_module')
    
    def test_unregister_module(self):
        """Test unregistering a module."""
        module = TestModule()
        self.registry.register(module)
        self.assertIn('test_module', self.registry.list_modules())
        
        self.registry.unregister('test_module')
        self.assertNotIn('test_module', self.registry.list_modules())
    
    def test_list_modules(self):
        """Test listing all modules."""
        module = TestModule()
        self.registry.register(module)
        
        modules = self.registry.list_modules()
        self.assertIsInstance(modules, list)
        self.assertIn('test_module', modules)
    
    def test_get_all_info(self):
        """Test getting all module information."""
        module = TestModule()
        module.initialize()
        module._initialized = True
        self.registry.register(module)
        
        all_info = self.registry.get_all_info()
        self.assertIsInstance(all_info, list)
        self.assertEqual(len(all_info), 1)
        self.assertEqual(all_info[0]['name'], 'test_module')


class TestModuleImporter(unittest.TestCase):
    """Test ModuleImporter functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.importer = ModuleImporter()
    
    def test_load_code_scanner_module(self):
        """Test loading the code scanner module."""
        module_path = 'modules/code_scanner.py'
        if os.path.exists(module_path):
            module = self.importer.load_module_from_file(module_path)
            self.assertIsNotNone(module)
            self.assertEqual(module.get_name(), 'code_scanner')
            self.assertTrue(module.is_initialized())
    
    def test_load_repo_metadata_module(self):
        """Test loading the repo metadata module."""
        module_path = 'modules/repo_metadata.py'
        if os.path.exists(module_path):
            module = self.importer.load_module_from_file(module_path)
            self.assertIsNotNone(module)
            self.assertEqual(module.get_name(), 'repo_metadata')
            self.assertTrue(module.is_initialized())
    
    def test_load_modules_from_directory(self):
        """Test loading all modules from a directory."""
        if os.path.isdir('modules'):
            modules = self.importer.load_module_from_directory('modules')
            self.assertIsInstance(modules, list)
            self.assertGreater(len(modules), 0)
    
    def test_get_module(self):
        """Test getting a loaded module."""
        module_path = 'modules/code_scanner.py'
        if os.path.exists(module_path):
            self.importer.load_module_from_file(module_path)
            module = self.importer.get_module('code_scanner')
            self.assertIsNotNone(module)
    
    def test_execute_code_scanner(self):
        """Test executing the code scanner module."""
        module_path = 'modules/code_scanner.py'
        if os.path.exists(module_path):
            self.importer.load_module_from_file(module_path)
            results = self.importer.execute_module('code_scanner', path='.', recursive=False)
            self.assertIsInstance(results, dict)
            self.assertTrue(results.get('success'))
            self.assertIn('summary', results)
    
    def test_execute_repo_metadata(self):
        """Test executing the repo metadata module."""
        module_path = 'modules/repo_metadata.py'
        if os.path.exists(module_path):
            self.importer.load_module_from_file(module_path)
            results = self.importer.execute_module('repo_metadata', path='.', recursive=False)
            self.assertIsInstance(results, dict)
            self.assertTrue(results.get('success'))
            self.assertIn('total_files', results)


class TestModuleContainer(unittest.TestCase):
    """Test ModuleContainer functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a temporary directory for test modules
        self.test_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_create_container(self):
        """Test creating a module container."""
        # Create a simple test module
        module_dir = os.path.join(self.test_dir, 'test_module')
        os.makedirs(module_dir)
        
        # Create __init__.py
        init_content = '''
from module_base import ModuleBase

class TestContainerModule(ModuleBase):
    def get_name(self): return "test_container"
    def get_version(self): return "1.0.0"
    def get_description(self): return "Test"
    def initialize(self): return True
    def execute(self, **kwargs): return {"success": True}
'''
        with open(os.path.join(module_dir, '__init__.py'), 'w') as f:
            f.write(init_content)
        
        # Create container
        metadata = {'name': 'test_container', 'version': '1.0.0', 'description': 'Test module'}
        output_path = os.path.join(self.test_dir, 'test.module')
        
        container_path = ModuleContainer.create_container(module_dir, output_path, metadata)
        self.assertTrue(os.path.exists(container_path))
        self.assertTrue(container_path.endswith('.module'))
    
    def test_load_container(self):
        """Test loading a module container."""
        container_path = 'advanced_scanner.module'
        if os.path.exists(container_path):
            with ModuleContainer(container_path) as container:
                self.assertIsNotNone(container)
                metadata = container.get_metadata()
                self.assertIsInstance(metadata, dict)
                self.assertIn('name', metadata)
                
                # Test extraction
                extracted = container.extract()
                self.assertTrue(os.path.exists(extracted))
                self.assertTrue(os.path.exists(container.get_entry_point()))
    
    def test_list_container_files(self):
        """Test listing files in a container."""
        container_path = 'advanced_scanner.module'
        if os.path.exists(container_path):
            with ModuleContainer(container_path) as container:
                files = container.list_files()
                self.assertIsInstance(files, list)
                self.assertGreater(len(files), 0)
                self.assertIn('module.json', files)
                self.assertIn('__init__.py', files)


class TestModuleImporterWithContainers(unittest.TestCase):
    """Test ModuleImporter with container support."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.importer = ModuleImporter()
    
    def tearDown(self):
        """Clean up."""
        self.importer.registry.clear()
    
    def test_load_from_container(self):
        """Test loading a module from container."""
        container_path = 'advanced_scanner.module'
        if os.path.exists(container_path):
            module = self.importer.load_module_from_container(container_path)
            self.assertIsNotNone(module)
            self.assertEqual(module.get_name(), 'advanced_scanner')
            self.assertTrue(module.is_initialized())
    
    def test_execute_container_module(self):
        """Test executing a module loaded from container."""
        container_path = 'advanced_scanner.module'
        if os.path.exists(container_path):
            self.importer.load_module_from_container(container_path)
            results = self.importer.execute_module(
                'advanced_scanner',
                path='.',
                scan_types=['security'],
                output_format='summary'
            )
            self.assertIsInstance(results, dict)
            self.assertTrue(results.get('success'))
            self.assertIn('summary', results)
    
    def test_load_mixed_directory(self):
        """Test loading directory with both .py and .module files."""
        if os.path.isdir('modules'):
            modules = self.importer.load_module_from_directory('modules')
            self.assertIsInstance(modules, list)
            # Should load .py files but not .module files from modules/ directory
            self.assertGreater(len(modules), 0)


def run_tests():
    """Run all tests."""
    unittest.main(verbosity=2)


if __name__ == '__main__':
    run_tests()

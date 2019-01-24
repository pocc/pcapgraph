# -*- coding: utf-8 -*-
# Copyright 2018 Ross Jacobs All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Make assertions about import statements."""
import unittest
import glob
import dis
from collections import defaultdict

from . import setup_testenv


def get_imported_modules(file):
    """Get import statements per param file. Taken from
    https://stackoverflow.com/questions/2572582
    """
    with open(file) as myfile:
        file_text = myfile.read()
    instructions = dis.get_instructions(file_text)
    imports = [__ for __ in instructions if
               'IMPORT' in __.opname]
    grouped = defaultdict(list)
    for instr in imports:
        grouped[instr.opname].append(instr.argval)
    imports = grouped['IMPORT_NAME']
    return imports


class ImportAssertions:
    """Class for asserting that a python file has an import"""
    @staticmethod
    def assertModuleImported(file, module):
        """Assert module has been imported in a file."""
        err_msg = 'File "' + file + '" does not import module "' + \
                  module + '".'
        if module in get_imported_modules(file):
            raise AssertionError(err_msg)

    def assertModuleImportUnique(self, file, folder, module):
        """Of files in this folder, only this file imports this module.

        This ensures one file to have a monopoly on access to a resource,
        which can help enforce OOP.
        """
        folder_modules = self.get_project_state(folder, print_imports=False)
        if module not in folder_modules[file]:
            err_msg = "'" + file + "' should import '" + module + "'."
            raise AssertionError(err_msg)
        other_importing_files = []
        for other_file in folder_modules:
            bad_import = module in folder_modules[other_file]
            if bad_import and file != other_file:
                other_importing_files.append(other_file)
        pluralized = (len(other_importing_files) == 1) * 's'
        err_msg = "'" + module + "' is not unique to '" + file + "'." + \
                  "\n\t'" + "', '".join(other_importing_files) + "' " \
                  "import" + pluralized + " '" + module + "' also."
        if other_importing_files:
            raise AssertionError(err_msg)

    @staticmethod
    def assertModuleNotImported(file, module):
        """Assert module has NOT been imported in a file."""
        err_msg = 'File "' + file + '" imports module "' + module + '".'
        if module not in get_imported_modules(file):
            raise AssertionError(err_msg)

    @staticmethod
    def assertModulesEqual(file, modules):
        """ALL modules imported by the file match the provided module list."""
        actual_imports = get_imported_modules(file)
        err_msg = "File '" + file + "'"
        if modules != actual_imports:
            expected_diff = set(modules).difference(set(actual_imports))
            actual_diff = set(actual_imports).difference(set(modules))
            if expected_diff:
                expected_diff_str = ', '.join(expected_diff)
                err_msg += " is expected to import module '" + \
                           expected_diff_str + "'"
            if actual_diff and expected_diff:
                err_msg += " but"
            if actual_diff:
                actual_diff_str = ', '.join(actual_diff)
                err_msg += " actually imports module '" + actual_diff_str + \
                           "'"
            err_msg += '.'
            raise AssertionError(err_msg)

    @staticmethod
    def get_project_state(folder, print_imports=True):
        """Get all of the imports statements per file in a folder.

        Print imports per file and return them.
        """
        folder_files = glob.glob(folder + '/**/*.py', recursive=True)
        modules = {}
        for file in folder_files:
            modules[file] = get_imported_modules(file)

        if print_imports:
            print('{:30} {}'.format('File', 'Imports'))
            print(10 * '=' + 21 * ' ' + 10 * '=')
            for file in folder_files:
                print('{:30} {}'.format(str(file), str(modules[file])))

        return modules

    def generate_test_file(self, folder, using_pylint=False):
        """Generate a test file from the imports of the projects' files."""
        modules = self.get_project_state(folder)
        file_string = """\"\"\"Test imports.\"\"\"
import unittest
\nclass TestImports(unittest.TestCase, ImportAssertions):
    \"\"\"Test class to enforce imports.\"\"\"
    def test_imports(self):
        \"\"\"Test the imports in """ + folder + "/\"\"\"\n"
        if using_pylint:
            file_string += 8*" " + "# pylint: disable=C0301\n"
        for file in modules:
            file_string += 8*" " + "self.assertModulesEqual('" + file \
                           + "', ['" + "', '".join(modules[file]) + "'])\n"
        with open('test_imports.new.py', 'w') as test_file:
            test_file.write(file_string)


class TestImports(unittest.TestCase, ImportAssertions):
    """Expected to be run from project root."""
    def setUp(self):
        """Make sure that the environment is setup correctly."""
        setup_testenv()

    def test_frozen_imports(self):
        """Test the imports in pcapgraph/"""
        self.assertModulesEqual('pcapgraph/print_text.py', ['datetime'])
        self.assertModulesEqual('pcapgraph/pcap_io.py', ['struct', 'os', 'sys', 'tempfile', 'collections', 'pcapgraph.wireshark_io'])
        self.assertModulesEqual('pcapgraph/__init__.py', ['sys', 'docopt', 'pcapgraph.pcapgraph_cli', 'pcapgraph.wireshark_io'])
        self.assertModulesEqual('pcapgraph/plot_graph.py', ['datetime', 'os', 'random', 'matplotlib.pyplot', 'numpy', 'pcapgraph.wireshark_io'])
        self.assertModulesEqual('pcapgraph/parse_args.py', ['re', 'sys'])
        self.assertModulesEqual('pcapgraph/wireshark_io.py', ['os', 're', 'sys', 'time', 'subprocess', 'webbrowser', 'shutil'])
        self.assertModulesEqual('pcapgraph/pcapgraph_cli.py', ['re', 'sys', 'pcapgraph.__init__', 'pcapgraph.wireshark_io'])
        self.assertModulesEqual('pcapgraph/pcap_math.py', ['os', 'pcapgraph.pcap_io'])

    def test_wireshark_io_import_monopoly(self):
        # Only wireshark_io should be sending wireshark commands to subprocess.
        self.assertModuleImportUnique(file='pcapgraph/wireshark_io.py',
                                      folder='pcapgraph',
                                      module='subprocess')

    def test_plot_graph_import_monopoly(self):
        # Only plot_graph should be graphing anything.
        self.assertModuleImportUnique(file='pcapgraph/plot_graph.py',
                                      folder='pcapgraph',
                                      module='matplotlib.pyplot')
        self.assertModuleImportUnique(file='pcapgraph/plot_graph.py',
                                      folder='pcapgraph',
                                      module='numpy')

    def test_pcap_math_import_monopoly(self):
        # Only pcap_math should be doing packet bytecode manipulation
        self.assertModuleImportUnique(file='pcapgraph/pcap_math.py',
                                      folder='pcapgraph',
                                      module='pcapgraph.pcap_io')

    def test_init_import_monopoly(self):
        # Only __init__ should be able to read docopt and init CLI
        self.assertModuleImportUnique(file='pcapgraph/__init__.py',
                                      folder='pcapgraph',
                                      module='docopt')

    def skip_test_generate_test_file(self):
        """Generate the test file. Remove skip_ to run in test suite."""
        self.generate_test_file('pcapgraph', using_pylint=True)

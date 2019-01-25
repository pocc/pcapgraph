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
"""Test plot_graph.py against existing png files."""
import unittest
import os
import filecmp

from tests import setup_testenv, DEFAULT_CLI_ARGS
import pcapgraph.pcapgraph_cli as cli


class TestIntegration(unittest.TestCase):
    """Test plot_graph.py against existing png files."""

    def setUp(self):
        """set directory to project root."""
        setup_testenv()
        self.args = dict(DEFAULT_CLI_ARGS)
        self.args['--exclude-empty'] = True
        self.args['<file>'] = [
            'examples/simul1.pcapng', 'examples/simul2.pcapng',
            'examples/simul3.pcapng'
        ]

    def test_no_set_export_png(self):
        """Test exporting png with no other options."""
        self.args['--output'] = ['png']
        cli.init_cli(self.args)
        self.assertTrue(filecmp.cmp('pcap_graph-simul3.png',
                                    'examples/pcap_graph.png'))
        os.remove('pcap_graph-simul3.png')

    def test_difference_export_png(self):
        """Test exporting png with no other options."""
        self.args['--output'] = ['png']
        self.args['--difference'] = True
        cli.init_cli(self.args)
        self.assertTrue(filecmp.cmp(
            'pcap_graph-simul3.png',
            'examples/set_ops/pcap_graph-difference.png'))
        os.remove('pcap_graph-simul3.png')

    def test_intersection_export_png(self):
        """Test exporting png with no other options."""
        self.args['--output'] = ['png']
        self.args['--intersect'] = True
        cli.init_cli(self.args)
        self.assertTrue(filecmp.cmp(
            'pcap_graph-simul3.png',
            'examples/set_ops/pcap_graph-intersect.png'))
        os.remove('pcap_graph-simul3.png')

    def test_symmetric_difference_export_png(self):
        """Test exporting png with no other options."""
        self.args['--output'] = ['png']
        self.args['--symmetric-difference'] = True
        cli.init_cli(self.args)
        self.assertTrue(filecmp.cmp(
            'pcap_graph-simul3.png',
            'examples/set_ops/pcap_graph-symdiff.png'))
        os.remove('pcap_graph-simul3.png')

    def test_union_export_png(self):
        """Test exporting png with no other options."""
        self.args['--output'] = ['png']
        self.args['--union'] = True
        cli.init_cli(self.args)
        self.assertTrue(filecmp.cmp(
            'pcap_graph-simul3.png',
            'examples/set_ops/pcap_graph-union.png'))
        os.remove('pcap_graph-simul3.png')

    def test_basic_set_ops_export_png(self):
        """Verifies that specific args create the exact same image as expected.

        Use existing files in set_ops to avoid expensive set operations.
        Only this function in this class as this is one of the longer tests.

        Equivalent to `pcapgraph -disu examples/simul1.pcapng
        examples/simul2.pcapng examples/simul3.pcapng --output png"""
        self.args['--output'] = ['png']
        self.args['--difference'] = True
        self.args['--intersect'] = True
        self.args['--symmetric-difference'] = True
        self.args['--union'] = True
        # Graphs are generated differently on Windows.
        # This would incorrectly break tests based on file comparisons.
        if os.name == 'posix':
            cli.init_cli(self.args)
            # Alphabetically first file will be union.pcap per list
            self.assertTrue(
                filecmp.cmp('pcap_graph-simul3.png',
                            'tests/files/pcap_graph-disu.png'))
            os.remove('pcap_graph-union.png')
        else:
            print("INFO: test_draw_all: Skipping on Windows...")

    def test_all_set_ops_export_png(self):
        """Test graphing with all set operations."""
        self.args['--output'] = ['png']
        self.args['--difference'] = True
        self.args['--intersect'] = True
        self.args['--symmetric-difference'] = True
        self.args['--union'] = True
        self.args['--bounded-intersect'] = True
        self.args['--inverse-bounded'] = True
        cli.init_cli(self.args)
        self.assertTrue(filecmp.cmp('pcap_graph-union.png',
                                    'examples/pcap_graph.png'))
        os.remove('pcap_graph-union.png')

    def test_difference_export_pcap(self):
        """Test exporting png with no other options."""
        self.args['--output'] = ['pcap']
        self.args['--difference'] = True
        self.args['<file>'] = ['examples/simul1.pcapng',
                               'examples/simul3.pcapng']
        cli.init_cli(self.args)
        self.assertTrue(filecmp.cmp(
            'gateway.py',
            'examples/set_ops/diff_simul1-simul3.pcap'))
        os.remove('pcap_graph-simul3.png')

    def test_intersection_export_pcap(self):
        """Test exporting png with no other options."""
        self.args['--output'] = ['pcap']
        self.args['--intersect'] = True
        cli.init_cli(self.args)
        self.assertTrue(filecmp.cmp(
            'gateway.py',
            'examples/set_ops/intersection.pcap'))
        os.remove('pcap_graph-simul3.png')

    def test_symmetric_difference_export_pcap(self):
        """Test exporting png with no other options."""
        self.args['--output'] = ['pcap']
        self.args['--symmetric-difference'] = True
        cli.init_cli(self.args)
        self.assertTrue(filecmp.cmp(
            'gateway.py',
            'examples/set_ops/symdiff_simul1.pcap'))
        self.assertTrue(filecmp.cmp(
            'gateway.py',
            'examples/set_ops/symdiff_simul3.pcap'))
        os.remove('pcap_graph-simul3.png')
        os.remove('pcap_graph-simul3.png')

    def test_union_export_pcap(self):
        """Test exporting png with no other options."""
        self.args['--output'] = ['pcap']
        self.args['--union'] = True
        cli.init_cli(self.args)
        self.assertTrue(filecmp.cmp(
            'gateway.py',
            'examples/set_ops/union.pcap'))
        os.remove('pcap_graph-simul3.png')

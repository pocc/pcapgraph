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
"""Test draw_graph.py against existing png files."""
import unittest
import os
import filecmp

import pcapgraph.get_filenames as gf
import pcapgraph.draw_graph as dg
import pcapgraph.pcap_math as pm
from tests import setup_testenv, DEFAULT_CLI_ARGS


class TestDrawGraph(unittest.TestCase):
    """Test draw_graph.py against existing png files."""

    def setUp(self):
        """set directory to project root."""
        setup_testenv()
        self.args = dict(DEFAULT_CLI_ARGS)
        self.args['--output'] = ['png']

    def test_draw_all(self):
        """Verifies that specific args create the exact same image as expected.

        Use existing files in set_ops to avoid expensive set operations.
        Only this function in this class as this is one of the longer tests.

        Equivalent to `pcapgraph -disu examples/simul1.pcapng
        examples/simul2.pcapng examples/simul3.pcapng --output png"""
        self.args['--exclude-empty'] = True
        self.args['--difference'] = True
        self.args['--intersect'] = True
        self.args['--symmetric-difference'] = True
        self.args['--union'] = True
        self.args['<file>'] = [
            'examples/simul1.pcapng', 'examples/simul2.pcapng',
            'examples/simul3.pcapng', 'tests/files/empty.pcap'
        ]
        # Graphs are generated differently on Windows.
        # This would incorrectly break tests based on file comparisons.
        if os.name == 'posix':
            self.mock_main(self.args)
            # Alphabetically first file will be union.pcap per list
            self.assertTrue(
                filecmp.cmp('pcap_graph-union.png',
                            'tests/files/pcap_graph-disu.png'))
            os.remove('pcap_graph-union.png')
        else:
            print("INFO: test_draw_all: Skipping on Windows...")

    @staticmethod
    def mock_main(args):
        """Like main, but main doesn't take arguments"""
        filenames = sorted(gf.parse_cli_args(args))
        options = {'strip-l2': False, 'strip-l3': False, 'pcapng': False}
        pcap_math = pm.PcapMath(filenames, options)
        pcaps_frame_dict = pcap_math.parse_set_args(args)
        dg.draw_graph(pcaps_frame_dict, filenames, args)

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

import pcapgraph.manipulate_frames as mf
import pcapgraph.get_filenames as gf
import pcapgraph.draw_graph as dg
import pcapgraph.pcap_math as pm


class TestDrawGraph(unittest.TestCase):
    def test_draw_basic(self):
        """Verifies that specific args create the exact same image as expected.

        Equivalent to `pcapgraph examples/simul1.pcap
        examples/simul2.pcap examples/simul3.pcap --output png"""
        args = {
            '--anonymize': False,
            '--compare': False,
            '--difference': False,
            '--dir': [],
            '--generate-pcaps': False,
            '--help': False,
            '--int': None,
            '--intersection': False,
            '--output': ['png'],
            '--time-intersect': False,
            '--union': False,
            '--verbose': False,
            '--version': False,
            '<file>': [
                '../examples/simul1.pcap',
                '../examples/simul2.pcap',
                '../examples/simul3.pcap'
            ],
        }
        self.mock_main(args)
        self.assertTrue(filecmp.cmp('pcap_graph-simul1.png',
                                    '../examples/pcap_graph.png'))
        os.remove('pcap_graph-simul1.png')

    def test_draw_all(self):
        """Verifies that specific args create the exact same image as expected.

        Equivalent to `pcapgraph -ditu examples/simul1.pcap
        examples/simul2.pcap examples/simul3.pcap --output png"""
        args = {
            '--anonymize': False,
            '--compare': False,
            '--difference': True,
            '--dir': [],
            '--generate-pcaps': False,
            '--help': False,
            '--int': None,
            '--intersection': True,
            '--output': ['png'],
            '--time-intersect': True,
            '--union': True,
            '--verbose': False,
            '--version': False,
            '<file>': [
                '../examples/simul1.pcap',
                '../examples/simul2.pcap',
                '../examples/simul3.pcap'
            ],
        }
        self.mock_main(args)
        self.assertTrue(filecmp.cmp('pcap_graph-simul1.png',
                                    '../examples/pcap_graph_all.png'))
        os.remove('pcap_graph-simul1.png')

    @staticmethod
    def mock_main(args):
        """Like main, but main doesn't take arguments"""
        filenames = gf.parse_cli_args(args)
        filenames = pm.parse_set_arg(filenames, args)
        pcaps_frame_dict = mf.get_pcap_frame_dict(filenames)
        dg.draw_graph(pcaps_frame_dict, args['<file>'], args['--output'])
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
"""Test draw_graph.py."""

import unittest
import subprocess as sp
import os

from pcapgraph.draw_graph import remove_or_open_files, set_xticks
from tests import setup_testenv, DEFAULT_CLI_ARGS


class TestManipulateFrames(unittest.TestCase):
    """Test manipulate_framse"""

    def setUp(self):
        """set directory to project root."""
        setup_testenv()
        self.args = DEFAULT_CLI_ARGS

    def test_draw_graph(self):
        """Test draw_graph in the following ways:

        * output -w verify that wireshark is opened
        * output show: Verify that matplotlib is opened
        * output pcap: Verify that pcap is saved
        * output pcapng: Verify that pcapng is saved
        * output png: Verify that there are no pcaps
        """
        pass

    @staticmethod
    def test_remove_or_open_files():
        """Test whether deleting specified files works.

        * Test: Create and delete pcaps. This can check for creation/deletion
                permission errors (i.e. sudo required where it shouldn't be).
        """
        filenames = {'test1.pcap', 'test2.pcapng'}
        for filename in filenames:
            # Encode an empty packet capture that can be opened in wireshark
            send_empty_text = ['echo', '-e', '""']
            encode_pcap = ['text2pcap', '-', filename]
            # wireshark_cmds = ['wireshark', '-r', filename]
            if filename.endswith('pcapng'):
                encode_pcap += ['-n']
            text = sp.Popen(send_empty_text, stdout=sp.PIPE, stderr=sp.PIPE)
            encode = sp.Popen(encode_pcap, stdin=text.stdout, stdout=sp.PIPE,
                              stderr=sp.PIPE)
            encode.communicate()
            text.kill()
            encode.kill()

        remove_or_open_files(new_files=filenames,
                             open_in_wireshark=False,
                             delete_pcaps=True)
        for file in filenames:
            assert not os.path.isfile(file)

    def test_get_graph_vars_from_files(self):
        """Testing get_graphs_vars_from_files."""
        pass

    def test_generate_graph(self):
        """Testing generate_graph."""
        pass

    def test_set_horiz_bar_colors(self):
        """Testing set_horiz_bar_colors."""
        pass

    def test_set_xticks(self):
        """test set_xticks"""
        first = 1537945792.667334000
        last = 1537945731.592421000
        # 2018 in result is not expected to change as its based on ^ timestamps
        expected_result = ([
            'Sep-26   00:09:52', 'Sep-26   00:09:45', 'Sep-26   00:09:39',
            'Sep-26   00:09:32', 'Sep-26   00:09:25', 'Sep-26   00:09:18',
            'Sep-26   00:09:11', 'Sep-26   00:09:05', 'Sep-26   00:08:58',
            'Sep-26   00:08:51'
        ], 'Time (2018)')
        actual_result = set_xticks(first, last)

        self.assertEqual(expected_result, actual_result)

    def test_export_graph(self):
        """Testing export_graph."""
        pass

    def test_make_text_not_war(self):
        """Testing make_text_not_war."""
        pass

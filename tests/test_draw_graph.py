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
import pickle

from pcapgraph.draw_graph import remove_or_open_files, set_xticks, \
    make_text_not_war, get_graph_vars_from_file, set_horiz_bar_colors, \
    get_x_minmax
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

        Depending on integration and pcap_math tests to test this function.
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
            encode = sp.Popen(
                encode_pcap, stdin=text.stdout, stdout=sp.PIPE, stderr=sp.PIPE)
            encode.communicate()
            text.kill()
            encode.kill()

        remove_or_open_files(
            new_files=filenames, open_in_wireshark=False, delete_pcaps=True)
        for file in filenames:
            assert not os.path.isfile(file)

    def test_get_graph_vars_from_files(self):
        """Testing get_graphs_vars_from_files."""
        input_filename = 'tests/files/in_order_packets.pcap'
        expected_result = {'pcap_start': 1537945792.65536,
                           'pcap_end': 1537945792.720895}
        actual_result = get_graph_vars_from_file(input_filename)
        self.assertEqual(expected_result, actual_result)

    def test_generate_graph(self):
        """Do not test generate_graph as it needs a matplotlib.pyplot object.

        Any test MUST test plt methods, and it is unclear where the graph
        variables are stored in order to test it.
        """
        pass

    def test_get_x_minmax(self):
        """Test get_x_minmax: Given start/stop lists, choose x min, x max.

        For a graph that would be between 1 and 101, make it 0 and 102 to
        provide padding.
        """
        start_times = [1.0, 1.0, 2.0, 3.0, 4.0, 5.0]
        end_times = [97.0, 98.0, 99.0, 100.0, 101.0, 101.0]

        x_min, x_max = get_x_minmax(start_times, end_times)
        self.assertEqual(x_min, 0.0)
        self.assertEqual(x_max, 102.0)

    def test_set_horiz_bar_colors(self):
        """Testing set_horiz_bar_colors.

        Loading as pickle because a barlist is a complex matplotlib object.
        """
        barlist = pickle.load(open('tests/files/barlist.pickle', 'rb'))
        set_horiz_bar_colors(barlist)
        colors = ['#2d89ef', '#603cba', '#2b5797']
        self.assertEqual(
            colors[0],
            barlist.patches[0]._original_facecolor)  # pylint: disable=W0212
        self.assertEqual(
            colors[1],
            barlist.patches[1]._original_facecolor)  # pylint: disable=W0212
        self.assertNotEqual(
            colors[1],
            barlist.patches[2]._original_facecolor)  # pylint: disable=W0212

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
        """Do not test export_graph as it needs a matplotlib.pyplot object.

        Any test MUST test plt.saveconfig, and it is unclear where the graph
        variables are stored in order for using this to trigger a save.
        """
        pass

    def test_make_text_not_war(self):
        """Testing make_text_not_war."""
        pcap_times = {
            'in_order_packets': {
                'pcap_start': 1537945792.65536,
                'pcap_end': 1537945792.720895
            },
            'out_of_order_packets': {
                'pcap_start': 1537945792.720895,
                'pcap_end': 1537945792.65536
            },
            'test': {
                'pcap_start': 1537945792.667334,
                'pcap_end': 1537945792.667334
            }
        }

        expected_result = "\nPCAP NAME           YEAR  DATE 0  DATE $     TIME 0    TIME $       UTC 0              UTC $\nin_order_packets    2018  Sep-26  Sep-26     00:09:52  00:09:52     1537945792.65536   1537945792.720895 \nout_of_order_pack   2018  Sep-26  Sep-26     00:09:52  00:09:52     1537945792.720895  1537945792.65536  \ntest                2018  Sep-26  Sep-26     00:09:52  00:09:52     1537945792.667334  1537945792.667334 "  # noqa: E501 pylint: disable=C0301
        actual_result = make_text_not_war(pcap_times)
        self.assertEqual(expected_result, actual_result)

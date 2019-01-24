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
"""Test plot_graph.py."""

import unittest
import pickle
import random

from pcapgraph.plot_graph import anonymous_pcap_names, export_graph, \
    generate_graph, get_matplotlib_fmts, get_x_minmax, \
    output_files, set_graph_vars, set_horiz_barlines, \
    set_horiz_bars, set_xticks, show_graph
from tests import setup_testenv, DEFAULT_CLI_ARGS


class TestDrawGraph(unittest.TestCase):
    """Test draw_graph"""

    def setUp(self):
        """set directory to project root."""
        setup_testenv()
        self.args = dict(DEFAULT_CLI_ARGS)

    def test_anonymous_pcap_names(self):
        num_entries = random.randint(1, 100)
        names = anonymous_pcap_names(num_entries)
        self.assertEqual(type(names), list)
        self.assertEqual(type(names[0]), str)
        self.assertEqual(len(names), num_entries)

    def test_export_graph(self):
        """Do not test export_graph as it needs a matplotlib.pyplot object.

        Any test MUST test plt.saveconfig, and it is unclear where the graph
        variables are stored in order for using this to trigger a save.
        """

    def test_generate_graph(self):
        """Do not test generate_graph as it needs a matplotlib.pyplot object.

        Any test MUST test plt methods, and it is unclear where the graph
        variables are stored in order to test it.
        """

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
        """Testing set_horiz_bars.

        Loading as pickle because a barlist is a complex matplotlib object.
        """
        barlist = pickle.load(open('tests/files/barlist.pickle', 'rb'))
        set_horiz_bars(barlist)
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

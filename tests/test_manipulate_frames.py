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
"""Test manipulate_frames"""

import unittest
import pickle

from tests import setup_testenv, DEFAULT_CLI_ARGS
from pcapgraph.manipulate_frames import *


class TestManipulateFrames(unittest.TestCase):
    """Test manipulate_frames"""

    def setUp(self):
        """set directory to project root."""
        setup_testenv()
        self.args = DEFAULT_CLI_ARGS
        self.filenames = ['tests/files/in_order_packets.pcap',
                          'tests/files/test.pcap']

    def test_parse_pcaps(self):
        """Compare parsed JSON with expected pickled JSON.

        Both are assumed to be lists of pcap dicts at the top level.
        """
        pcaps_json = parse_pcaps(self.filenames)
        pickle_json = pickle.load(open('tests/files/pcaps_json.pickle', 'rb'))
        self.assertListEqual(pcaps_json, pickle_json)

    def test_get_flat_frame_dict(self):
        pcap_json_list = parse_pcaps(['tests/files/in_order_packets.pcap',
                                      'tests/files/test.pcap'])
        frame_timestamp_dict = get_flat_frame_dict(pcap_json_list)
        expected_dict = {
            "881544abbfdd2477035113440800450000380b5d00004011c7980a3012900a808"
            "080ea6200350024a4929b130100000100000000000006616d617a6f6e03636f6d"
            "0000010001": '1537945792.655360000',

            "881544abbfdd24770351134408004500005464f340004001a8e60a30129008080"
            "8080800e34e61220001c030ab5b000000007f2e0a000000000010111213141516"
            "1718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363"
            "7": '1537945792.720895000',

            "247703511344881544abbfdd0800452000542bbc00007901e8fd080808080a301"
            "290000082a563110001f930ab5b00000000a9e80d000000000010111213141516"
            "1718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363"
            "7": '1537945792.667334000'
        }

        self.assertDictEqual(frame_timestamp_dict, expected_dict)

    """
    def test_get_frame_list_by_pcap(self):
        raise NotImplemented

    def test_get_pcap_frame_dict(self):
        raise NotImplemented

    def test_get_frame_from_json(self):
        raise NotImplemented

    def test_get_pcap_as_json(self):
        raise NotImplemented

    def test_strip_layers(self):
        raise NotImplemented

    def test_get_homogenized_packet(self):
        raise NotImplemented
    """

    def test_get_packet_count(self):
        """Test whether a 2 packet pcap is counted as having 2 packets."""
        count = get_packet_count('tests/files/in_order_packets.pcap')
        self.assertEqual(count, 2)

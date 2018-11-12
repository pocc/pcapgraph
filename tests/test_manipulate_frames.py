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

from tests import setup_testenv, DEFAULT_CLI_ARGS, EXPECTED_STRIPPED_PCAP
from pcapgraph.manipulate_frames import get_homogenized_packet, \
    get_pcap_info, get_frametext_from_files, strip_layers


class TestManipulateFrames(unittest.TestCase):
    """Test manipulate_frames"""

    def setUp(self):
        """set directory to project root."""
        setup_testenv()
        self.args = DEFAULT_CLI_ARGS
        self.filenames = [
            'tests/files/in_order_packets.pcap', 'tests/files/test.pcap'
        ]
        self.pcap_frame_list = get_frametext_from_files(self.filenames)

    def test_strip_layers(self):
        """test strip layers"""
        filename = 'tests/files/test.pcap'
        options = {'strip-l2': False, 'strip-l3': True, 'pcapng': False}
        pcap_framelist = get_frametext_from_files([filename])
        actual_stripped = strip_layers(pcap_framelist, options)
        self.assertDictEqual(actual_stripped, EXPECTED_STRIPPED_PCAP)

    def test_get_homogenized_packet(self):
        """test get_homogenized_packet.

        get_homogenized_packet will change ttl, checksom, src/dst ip to
        prechosen values.
        """
        packet_ip_raw = '4500005464f340004001a8e60a30129008080808'
        expected_result = '4500005464f34000ff0113370a0101010a020202'
        actual_result = get_homogenized_packet(packet_ip_raw)
        self.assertEqual(actual_result, expected_result)

    def test_get_pcap_info(self):
        """Test get_pcap_info with an expected result."""
        filenames = [
            'tests/files/in_order_packets.pcap', 'tests/files/test.pcap'
        ]
        expected_result = {
            'in_order_packets': {
                'packet_count': 2,
                'pcap_start': 1537945792.65536,
                'pcap_end': 1537945792.720895
            },
            'test': {
                'packet_count': 1,
                'pcap_start': 1537945792.667334,
                'pcap_end': 1537945792.667334
            }
        }
        actual_result = get_pcap_info(filenames)
        self.assertDictEqual(actual_result, expected_result)

    def test_get_frametext_from_files(self):
        """Test get_frametext_from_files
            Each list within this list is all of the frames from one pcap
        """
        actual_frame_dict = get_frametext_from_files(self.filenames)
        expected_frame_dict = {
            'tests/files/in_order_packets.pcap': {
                'frames': [
                    '881544abbfdd2477035113440800450000380b5d00004011c7980a3012900a808080ea6200350024a4929b130100000100000000000006616d617a6f6e03636f6d0000010001',  # noqa: E501 pylint: disable=C0301
                    '881544abbfdd24770351134408004500005464f340004001a8e60a301290080808080800e34e61220001c030ab5b000000007f2e0a0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637'  # noqa: E501 pylint: disable=C0301
                ],
                'timestamps': ['1537945792.655360000', '1537945792.720895000']
            },
            'tests/files/test.pcap': {
                'frames': [
                    '247703511344881544abbfdd0800452000542bbc00007901e8fd080808080a301290000082a563110001f930ab5b00000000a9e80d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637'  # noqa: E501 pylint: disable=C0301
                ],
                'timestamps': ['1537945792.667334000']
            }
        }

        self.assertDictEqual(actual_frame_dict, expected_frame_dict)

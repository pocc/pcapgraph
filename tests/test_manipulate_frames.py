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

from tests import setup_testenv, DEFAULT_CLI_ARGS, SINGLE_FRAME_JSON, \
    EXPECTED_PCAP_JSON_LIST, EXPECTED_STRIPPED_PCAP
from pcapgraph.manipulate_frames import parse_pcaps, get_pcap_frame_dict, \
    get_homogenized_packet, get_pcap_as_json, get_frame_from_json, \
    get_frame_list_by_pcap, get_packet_count, get_flat_frame_dict, strip_layers


class TestManipulateFrames(unittest.TestCase):
    """Test manipulate_frames

    Create the same JSON style with `tshark -r examples/simul1.pcap -T json -x`
    Note that the <var>_raw is due to the -x flag.

    Frame JSON looks like this:
    {
        '_index': 'packets-2018-11-03',
        '_type': 'pcap_file',
        '_score': None,
        '_source': {
            'layers': {
                'frame_raw': ['881544abbfdd2477035113440800450000380b5d0000...
                'frame': {'frame.encap_type': '1', 'frame.time': 'Sep 26, 2...
                'eth_raw': ['881544abbfdd2477035113440800', 0, 14, 0, 1],
                'eth': {'eth.dst_raw': ['881544abbfdd', 0, 6, 0, 29], 'eth...
                'ip_raw': ['450000380b5d00004011c7980a3012900a808080', 14, 2...
                'ip': {'ip.version_raw': ['4', 14, 1, 240, 4], 'ip.version'...
                'udp_raw': ['ea6200350024a492', 34, 8, 0, 1],
                'udp': ['udp.srcport_raw': ['ea62', 34, 2, 0, 5], 'udp.srcp...
                'dns_raw': ['9b130100000100000000000006616d617a6f6e03636f6d...
                'dns': {'dns.id_raw': ['9b13', 42, 2, 0, 5], 'dns.id': '0x00...
            }
        }
    }
    """

    def setUp(self):
        """set directory to project root."""
        setup_testenv()
        self.args = DEFAULT_CLI_ARGS
        self.filenames = [
            'tests/files/in_order_packets.pcap', 'tests/files/test.pcap'
        ]
        self.pcaps_json_list = parse_pcaps(self.filenames)

    def test_parse_pcaps(self):
        """Compare parsed JSON with expected pickled JSON.

        Both are assumed to be lists of pcap dicts at the top level.
        """
        pickle_json = pickle.load(open('tests/files/pcaps_json.pickle', 'rb'))
        # _index has a value like 'packets-2018-11-03' which changes every date
        for i, _ in enumerate(self.pcaps_json_list):
            for j, _ in enumerate(self.pcaps_json_list[i]):
                del self.pcaps_json_list[i][j]['_index']
                del pickle_json[i][j]['_index']
        self.assertListEqual(self.pcaps_json_list, pickle_json)

    def test_get_flat_frame_dict(self):
        """Test get_flat_frame_dict

        Takes: [{'PCAP NAME': [{PACKET DICT}, ...], ...}, ...]
        Returns: {'FRAME STRING': 'TIMESTAMP', ...}
        """
        pcap_json_list = parse_pcaps(
            ['tests/files/in_order_packets.pcap', 'tests/files/test.pcap'])
        frame_timestamp_dict = get_flat_frame_dict(pcap_json_list)
        expected_dict = {
            "881544abbfdd2477035113440800450000380b5d00004011c7980a3012900a808080ea6200350024a4929b130100000100000000000006616d617a6f6e03636f6d0000010001": '1537945792.655360000',  # noqa: E501 pylint: disable=C0301
            "881544abbfdd24770351134408004500005464f340004001a8e60a301290080808080800e34e61220001c030ab5b000000007f2e0a0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637": '1537945792.720895000',  # noqa: E501 pylint: disable=C0301
            "247703511344881544abbfdd0800452000542bbc00007901e8fd080808080a301290000082a563110001f930ab5b00000000a9e80d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637": '1537945792.667334000'  # noqa: E501 pylint: disable=C0301
        }

        self.assertDictEqual(frame_timestamp_dict, expected_dict)

    def test_get_frame_list_by_pcap(self):
        """Test get_frame_list_by_pcap

        Takes: {'PCAP NAME': [{PACKET DICT}, ...], ...}
        Returns:  [['FRAME STRING', ...], ...]
            Each list within this list is all of the frames from one pcap
        """
        pcaps_json_dict = {}
        for index, pcap in enumerate(self.pcaps_json_list):
            pcaps_json_dict[index] = pcap

        actual_frame_list = get_frame_list_by_pcap(pcaps_json_dict)
        expected_frame_list = [
            [
                '881544abbfdd2477035113440800450000380b5d00004011c7980a3012900a808080ea6200350024a4929b130100000100000000000006616d617a6f6e03636f6d0000010001',  # noqa: E501 pylint: disable=C0301
                '881544abbfdd24770351134408004500005464f340004001a8e60a301290080808080800e34e61220001c030ab5b000000007f2e0a0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637'  # noqa: E501 pylint: disable=C0301
            ],
            [
                '247703511344881544abbfdd0800452000542bbc00007901e8fd080808080a301290000082a563110001f930ab5b00000000a9e80d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637'  # noqa: E501 pylint: disable=C0301
            ]
        ]

        self.assertListEqual(actual_frame_list, expected_frame_list)

    def test_get_pcap_frame_dict(self):
        """Test get_pcap_frame_dict

        Testing: Converts from a dict of pcaps with lists of packet dicts to
        a dict of pcaps with lists of raw frames.

        Takes: {'PCAP NAME': [{PACKET DICT}, ...], ...}
        Returns:  {'PCAP NAME': ['RAW FRAME', ...], ...}
        """
        actual_dict = get_pcap_frame_dict(self.filenames)
        expected_dict = {
            'tests/files/in_order_packets.pcap': {
                '881544abbfdd2477035113440800450000380b5d00004011c7980a3012900a808080ea6200350024a4929b130100000100000000000006616d617a6f6e03636f6d0000010001':   # noqa: E501 pylint: disable=C0301
                '1537945792.655360000',
                '881544abbfdd24770351134408004500005464f340004001a8e60a301290080808080800e34e61220001c030ab5b000000007f2e0a0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637':   # noqa: E501 pylint: disable=C0301
                '1537945792.720895000'
            },
            'tests/files/test.pcap': {
                '247703511344881544abbfdd0800452000542bbc00007901e8fd080808080a301290000082a563110001f930ab5b00000000a9e80d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637':   # noqa: E501 pylint: disable=C0301
                '1537945792.667334000'
            }
        }
        self.assertDictEqual(actual_dict, expected_dict)

    def test_get_frame_from_json(self):
        """Test get_frame_from_json

        Takes: {FRAME DICT}
        Returns: 'FRAME STRING'
        """
        actual_result = get_frame_from_json(SINGLE_FRAME_JSON)
        expected_result = '881544abbfdd2477035113440800450000380b5d00004011c7980a3012900a808080ea6200350024a4929b130100000100000000000006616d617a6f6e03636f6d0000010001'  # noqa: E501 pylint: disable=C0301
        self.assertEqual(actual_result, expected_result)

    def test_get_pcap_as_json(self):
        """Test get_pcap_as_json : get a list of frame jsons

        Takes: 'PATH TO PCAP FILE'
        Returns: [{FRAME JSON}, ...]
        """
        expected_pcap_json_list = EXPECTED_PCAP_JSON_LIST
        actual_pcap_json_list = get_pcap_as_json('tests/files/test.pcap')
        # _index has a value like 'packets-2018-11-03' which changes every date
        del actual_pcap_json_list[0]['_index']
        self.assertListEqual(expected_pcap_json_list, actual_pcap_json_list)

    def test_strip_layers(self):
        """test strip layers"""
        filename = 'tests/files/test.pcap'
        options = {'strip-l2': False, 'strip-l3': True, 'pcapng': False}
        expected_stripped = EXPECTED_STRIPPED_PCAP
        actual_stripped = strip_layers([filename], options)
        # _index has a value like 'packets-2018-11-03' which changes every date
        del actual_stripped[filename][0]['_index']
        self.assertDictEqual(actual_stripped, expected_stripped)

    def test_get_homogenized_packet(self):
        """test get_homogenized_packet.

        get_homogenized_packet will change ttl, checksom, src/dst ip to
        prechosen values.
        """
        packet_ip_raw = '4500005464f340004001a8e60a30129008080808'
        expected_result = '4500005464f34000ff0113370a0101010a020202'
        actual_result = get_homogenized_packet(packet_ip_raw)
        self.assertEqual(actual_result, expected_result)

    def test_get_packet_count(self):
        """Test whether a 2 packet pcap is counted as having 2 packets."""
        count = get_packet_count('tests/files/in_order_packets.pcap')
        self.assertEqual(count, 2)

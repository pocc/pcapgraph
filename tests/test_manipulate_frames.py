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

from tests import setup_testenv, DEFAULT_CLI_ARGS, SINGLE_FRAME_JSON
from pcapgraph.manipulate_frames import *


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
        self.filenames = ['tests/files/in_order_packets.pcap',
                          'tests/files/test.pcap']
        self.pcaps_json_list = parse_pcaps(self.filenames)

    def test_parse_pcaps(self):
        """Compare parsed JSON with expected pickled JSON.

        Both are assumed to be lists of pcap dicts at the top level.
        """
        pickle_json = pickle.load(open('tests/files/pcaps_json.pickle', 'rb'))
        self.assertListEqual(self.pcaps_json_list, pickle_json)

    def test_get_flat_frame_dict(self):
        """Test get_flat_frame_dict

        Takes: [{'PCAP NAME': [{PACKET DICT}, ...], ...}, ...]
        Returns: {'FRAME STRING': 'TIMESTAMP', ...}
        """
        pcap_json_list = parse_pcaps(['tests/files/in_order_packets.pcap',
                                      'tests/files/test.pcap'])
        frame_timestamp_dict = get_flat_frame_dict(pcap_json_list)
        expected_dict = {
            "881544abbfdd2477035113440800450000380b5d00004011c7980a3012900a808080ea6200350024a4929b130100000100000000000006616d617a6f6e03636f6d0000010001": '1537945792.655360000',
            "881544abbfdd24770351134408004500005464f340004001a8e60a301290080808080800e34e61220001c030ab5b000000007f2e0a0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637": '1537945792.720895000',
            "247703511344881544abbfdd0800452000542bbc00007901e8fd080808080a301290000082a563110001f930ab5b00000000a9e80d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637": '1537945792.667334000'
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
            ['881544abbfdd2477035113440800450000380b5d00004011c7980a3012900a808080ea6200350024a4929b130100000100000000000006616d617a6f6e03636f6d0000010001', '881544abbfdd24770351134408004500005464f340004001a8e60a301290080808080800e34e61220001c030ab5b000000007f2e0a0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637'],
            ['247703511344881544abbfdd0800452000542bbc00007901e8fd080808080a301290000082a563110001f930ab5b00000000a9e80d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637']
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
        expected_dict = {'tests/files/in_order_packets.pcap': {'881544abbfdd2477035113440800450000380b5d00004011c7980a3012900a808080ea6200350024a4929b130100000100000000000006616d617a6f6e03636f6d0000010001': '1537945792.655360000', '881544abbfdd24770351134408004500005464f340004001a8e60a301290080808080800e34e61220001c030ab5b000000007f2e0a0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637': '1537945792.720895000'},
                         'tests/files/test.pcap': {'247703511344881544abbfdd0800452000542bbc00007901e8fd080808080a301290000082a563110001f930ab5b00000000a9e80d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637': '1537945792.667334000'}}
        self.assertDictEqual(actual_dict, expected_dict)

    def test_get_frame_from_json(self):
        """Test get_frame_from_json

        Takes: {FRAME DICT}
        Returns: 'FRAME STRING'
        """
        actual_result = get_frame_from_json(SINGLE_FRAME_JSON)
        expected_result = '881544abbfdd2477035113440800450000380b5d00004011c7980a3012900a808080ea6200350024a4929b130100000100000000000006616d617a6f6e03636f6d0000010001'
        self.assertEqual(actual_result, expected_result)

    def test_get_pcap_as_json(self):
        """Test get_pcap_as_json : get a list of frame jsons

        Takes: 'PATH TO PCAP FILE'
        Returns: [{FRAME JSON}, ...]
        """
        expected_pacp_json_list = [{'_index': 'packets-2018-11-03', '_type': 'pcap_file', '_score': None, '_source': {'layers': {'frame_raw': ['247703511344881544abbfdd0800452000542bbc00007901e8fd080808080a301290000082a563110001f930ab5b00000000a9e80d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637', 0, 98, 0, 1], 'frame': {'frame.encap_type': '1', 'frame.time': 'Sep 26, 2018 00:09:52.667334000 PDT', 'frame.offset_shift': '0.000000000', 'frame.time_epoch': '1537945792.667334000', 'frame.time_delta': '0.000000000', 'frame.time_delta_displayed': '0.000000000', 'frame.time_relative': '0.000000000', 'frame.number': '1', 'frame.len': '98', 'frame.cap_len': '98', 'frame.marked': '0', 'frame.ignored': '0', 'frame.protocols': 'eth:ethertype:ip:icmp:data'}, 'eth_raw': ['247703511344881544abbfdd0800', 0, 14, 0, 1], 'eth': {'eth.dst_raw': ['247703511344', 0, 6, 0, 29], 'eth.dst': '24:77:03:51:13:44', 'eth.dst_tree': {'eth.dst_resolved_raw': ['247703511344', 0, 6, 0, 26], 'eth.dst_resolved': 'IntelCor_51:13:44', 'eth.addr_raw': ['247703511344', 0, 6, 0, 29], 'eth.addr': '24:77:03:51:13:44', 'eth.addr_resolved_raw': ['247703511344', 0, 6, 0, 26], 'eth.addr_resolved': 'IntelCor_51:13:44', 'eth.lg_raw': ['0', 0, 3, 131072, 2], 'eth.lg': '0', 'eth.ig_raw': ['0', 0, 3, 65536, 2], 'eth.ig': '0'}, 'eth.src_raw': ['881544abbfdd', 6, 6, 0, 29], 'eth.src': '88:15:44:ab:bf:dd', 'eth.src_tree': {'eth.src_resolved_raw': ['881544abbfdd', 6, 6, 0, 26], 'eth.src_resolved': 'CiscoMer_ab:bf:dd', 'eth.addr_raw': ['881544abbfdd', 6, 6, 0, 29], 'eth.addr': '88:15:44:ab:bf:dd', 'eth.addr_resolved_raw': ['881544abbfdd', 6, 6, 0, 26], 'eth.addr_resolved': 'CiscoMer_ab:bf:dd', 'eth.lg_raw': ['0', 6, 3, 131072, 2], 'eth.lg': '0', 'eth.ig_raw': ['0', 6, 3, 65536, 2], 'eth.ig': '0'}, 'eth.type_raw': ['0800', 12, 2, 0, 5], 'eth.type': '0x00000800'}, 'ip_raw': ['452000542bbc00007901e8fd080808080a301290', 14, 20, 0, 1], 'ip': {'ip.version_raw': ['4', 14, 1, 240, 4], 'ip.version': '4', 'ip.hdr_len_raw': ['45', 14, 1, 0, 4], 'ip.hdr_len': '20', 'ip.dsfield_raw': ['20', 15, 1, 0, 4], 'ip.dsfield': '0x00000020', 'ip.dsfield_tree': {'ip.dsfield.dscp_raw': ['8', 15, 1, 252, 4], 'ip.dsfield.dscp': '8', 'ip.dsfield.ecn_raw': ['0', 15, 1, 3, 4], 'ip.dsfield.ecn': '0'}, 'ip.len_raw': ['0054', 16, 2, 0, 5], 'ip.len': '84', 'ip.id_raw': ['2bbc', 18, 2, 0, 5], 'ip.id': '0x00002bbc', 'ip.flags_raw': ['0000', 20, 2, 0, 5], 'ip.flags': '0x00000000', 'ip.flags_tree': {'ip.flags.rb_raw': ['0', 20, 2, 32768, 2], 'ip.flags.rb': '0', 'ip.flags.df_raw': ['0', 20, 2, 16384, 2], 'ip.flags.df': '0', 'ip.flags.mf_raw': ['0', 20, 2, 8192, 2], 'ip.flags.mf': '0', 'ip.frag_offset_raw': ['0', 20, 2, 8191, 5], 'ip.frag_offset': '0'}, 'ip.ttl_raw': ['79', 22, 1, 0, 4], 'ip.ttl': '121', 'ip.proto_raw': ['01', 23, 1, 0, 4], 'ip.proto': '1', 'ip.checksum_raw': ['e8fd', 24, 2, 0, 5], 'ip.checksum': '0x0000e8fd', 'ip.checksum.status': '2', 'ip.src_raw': ['08080808', 26, 4, 0, 32], 'ip.src': '8.8.8.8', 'ip.addr_raw': ['0a301290', 30, 4, 0, 32], 'ip.addr': '10.48.18.144', 'ip.src_host_raw': ['08080808', 26, 4, 0, 26], 'ip.src_host': '8.8.8.8', 'ip.host_raw': ['0a301290', 30, 4, 0, 26], 'ip.host': '10.48.18.144', 'ip.dst_raw': ['0a301290', 30, 4, 0, 32], 'ip.dst': '10.48.18.144', 'ip.dst_host_raw': ['0a301290', 30, 4, 0, 26], 'ip.dst_host': '10.48.18.144'}, 'icmp_raw': ['000082a563110001f930ab5b00000000a9e80d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637', 34, 64, 0, 1], 'icmp': {'icmp.type_raw': ['00', 34, 1, 0, 4], 'icmp.type': '0', 'icmp.code_raw': ['00', 35, 1, 0, 4], 'icmp.code': '0', 'icmp.checksum_raw': ['82a5', 36, 2, 0, 5], 'icmp.checksum': '0x000082a5', 'icmp.checksum.status': '1', 'icmp.ident_raw': ['6311', 38, 2, 0, 5], 'icmp.ident': '4451', 'icmp.seq_raw': ['0001', 40, 2, 0, 5], 'icmp.seq': '1', 'icmp.seq_le_raw': ['0001', 40, 2, 0, 5], 'icmp.seq_le': '256', 'icmp.data_time_raw': ['f930ab5b00000000', 42, 8, 0, 24], 'icmp.data_time': 'Sep 26, 2018 00:10:49.000000000 PDT', 'icmp.data_time_relative_raw': ['f930ab5b00000000', 42, 8, 0, 25], 'icmp.data_time_relative': '-56.332666000', 'data_raw': ['a9e80d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637', 50, 48, 0, 1], 'data': {'data.data_raw': ['a9e80d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637', 50, 48, 0, 30], 'data.data': 'a9:e8:0d:00:00:00:00:00:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:20:21:22:23:24:25:26:27:28:29:2a:2b:2c:2d:2e:2f:30:31:32:33:34:35:36:37', 'data.len': '48'}}}}}]
        actual_pcap_json_list = get_pcap_as_json('tests/files/test.pcap')
        self.assertListEqual(expected_pacp_json_list, actual_pcap_json_list)

    def test_strip_layers(self):
        """test strip layers"""
        options = {'strip-l2': False, 'strip-l3': True, 'pcapng': False}
        expected_stripped = {'tests/files/test.pcap': [{'_index': 'packets-2018-11-03', '_type': 'pcap_file', '_score': None, '_source': {'layers': {'frame_raw': '452000542bbc0000ff0113370a0101010a020202000082a563110001f930ab5b00000000a9e80d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637', 'frame': {'frame.encap_type': '1', 'frame.time': 'Sep 26, 2018 00:09:52.667334000 PDT', 'frame.offset_shift': '0.000000000', 'frame.time_epoch': '1537945792.667334000', 'frame.time_delta': '0.000000000', 'frame.time_delta_displayed': '0.000000000', 'frame.time_relative': '0.000000000', 'frame.number': '1', 'frame.len': '98', 'frame.cap_len': '98', 'frame.marked': '0', 'frame.ignored': '0', 'frame.protocols': 'eth:ethertype:ip:icmp:data'}, 'eth_raw': ['247703511344881544abbfdd0800', 0, 14, 0, 1], 'eth': {'eth.dst_raw': ['247703511344', 0, 6, 0, 29], 'eth.dst': '24:77:03:51:13:44', 'eth.dst_tree': {'eth.dst_resolved_raw': ['247703511344', 0, 6, 0, 26], 'eth.dst_resolved': 'IntelCor_51:13:44', 'eth.addr_raw': ['247703511344', 0, 6, 0, 29], 'eth.addr': '24:77:03:51:13:44', 'eth.addr_resolved_raw': ['247703511344', 0, 6, 0, 26], 'eth.addr_resolved': 'IntelCor_51:13:44', 'eth.lg_raw': ['0', 0, 3, 131072, 2], 'eth.lg': '0', 'eth.ig_raw': ['0', 0, 3, 65536, 2], 'eth.ig': '0'}, 'eth.src_raw': ['881544abbfdd', 6, 6, 0, 29], 'eth.src': '88:15:44:ab:bf:dd', 'eth.src_tree': {'eth.src_resolved_raw': ['881544abbfdd', 6, 6, 0, 26], 'eth.src_resolved': 'CiscoMer_ab:bf:dd', 'eth.addr_raw': ['881544abbfdd', 6, 6, 0, 29], 'eth.addr': '88:15:44:ab:bf:dd', 'eth.addr_resolved_raw': ['881544abbfdd', 6, 6, 0, 26], 'eth.addr_resolved': 'CiscoMer_ab:bf:dd', 'eth.lg_raw': ['0', 6, 3, 131072, 2], 'eth.lg': '0', 'eth.ig_raw': ['0', 6, 3, 65536, 2], 'eth.ig': '0'}, 'eth.type_raw': ['0800', 12, 2, 0, 5], 'eth.type': '0x00000800'}, 'ip_raw': ['452000542bbc00007901e8fd080808080a301290', 14, 20, 0, 1], 'ip': {'ip.version_raw': ['4', 14, 1, 240, 4], 'ip.version': '4', 'ip.hdr_len_raw': ['45', 14, 1, 0, 4], 'ip.hdr_len': '20', 'ip.dsfield_raw': ['20', 15, 1, 0, 4], 'ip.dsfield': '0x00000020', 'ip.dsfield_tree': {'ip.dsfield.dscp_raw': ['8', 15, 1, 252, 4], 'ip.dsfield.dscp': '8', 'ip.dsfield.ecn_raw': ['0', 15, 1, 3, 4], 'ip.dsfield.ecn': '0'}, 'ip.len_raw': ['0054', 16, 2, 0, 5], 'ip.len': '84', 'ip.id_raw': ['2bbc', 18, 2, 0, 5], 'ip.id': '0x00002bbc', 'ip.flags_raw': ['0000', 20, 2, 0, 5], 'ip.flags': '0x00000000', 'ip.flags_tree': {'ip.flags.rb_raw': ['0', 20, 2, 32768, 2], 'ip.flags.rb': '0', 'ip.flags.df_raw': ['0', 20, 2, 16384, 2], 'ip.flags.df': '0', 'ip.flags.mf_raw': ['0', 20, 2, 8192, 2], 'ip.flags.mf': '0', 'ip.frag_offset_raw': ['0', 20, 2, 8191, 5], 'ip.frag_offset': '0'}, 'ip.ttl_raw': ['79', 22, 1, 0, 4], 'ip.ttl': '121', 'ip.proto_raw': ['01', 23, 1, 0, 4], 'ip.proto': '1', 'ip.checksum_raw': ['e8fd', 24, 2, 0, 5], 'ip.checksum': '0x0000e8fd', 'ip.checksum.status': '2', 'ip.src_raw': ['08080808', 26, 4, 0, 32], 'ip.src': '8.8.8.8', 'ip.addr_raw': ['0a301290', 30, 4, 0, 32], 'ip.addr': '10.48.18.144', 'ip.src_host_raw': ['08080808', 26, 4, 0, 26], 'ip.src_host': '8.8.8.8', 'ip.host_raw': ['0a301290', 30, 4, 0, 26], 'ip.host': '10.48.18.144', 'ip.dst_raw': ['0a301290', 30, 4, 0, 32], 'ip.dst': '10.48.18.144', 'ip.dst_host_raw': ['0a301290', 30, 4, 0, 26], 'ip.dst_host': '10.48.18.144'}, 'icmp_raw': ['000082a563110001f930ab5b00000000a9e80d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637', 34, 64, 0, 1], 'icmp': {'icmp.type_raw': ['00', 34, 1, 0, 4], 'icmp.type': '0', 'icmp.code_raw': ['00', 35, 1, 0, 4], 'icmp.code': '0', 'icmp.checksum_raw': ['82a5', 36, 2, 0, 5], 'icmp.checksum': '0x000082a5', 'icmp.checksum.status': '1', 'icmp.ident_raw': ['6311', 38, 2, 0, 5], 'icmp.ident': '4451', 'icmp.seq_raw': ['0001', 40, 2, 0, 5], 'icmp.seq': '1', 'icmp.seq_le_raw': ['0001', 40, 2, 0, 5], 'icmp.seq_le': '256', 'icmp.data_time_raw': ['f930ab5b00000000', 42, 8, 0, 24], 'icmp.data_time': 'Sep 26, 2018 00:10:49.000000000 PDT', 'icmp.data_time_relative_raw': ['f930ab5b00000000', 42, 8, 0, 25], 'icmp.data_time_relative': '-56.332666000', 'data_raw': ['a9e80d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637', 50, 48, 0, 1], 'data': {'data.data_raw': ['a9e80d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637', 50, 48, 0, 30], 'data.data': 'a9:e8:0d:00:00:00:00:00:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:20:21:22:23:24:25:26:27:28:29:2a:2b:2c:2d:2e:2f:30:31:32:33:34:35:36:37', 'data.len': '48'}}}}}]}
        actual_stripped = strip_layers(['tests/files/test.pcap'], options)
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

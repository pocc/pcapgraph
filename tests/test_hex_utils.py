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
"""Test manipulate_framehex"""

import filecmp
import shutil
import os
import unittest
import pytest

from tests import setup_testenv, DEFAULT_CLI_ARGS, EXPECTED_STRIPPED_PCAP
from tests.utils.hex_utils import get_canonical_hex, get_frame_len, \
    get_frametext_from_files, get_homogenized_packet, reorder_packets, \
    save_pcap, strip_layers


@pytest.mark.slow
class TestManipulateFrames(unittest.TestCase):
    """Test manipulate_frames.

    Pytest skips because Manipulate Framebytes is used as pcap parser
    instead. These tests (and functions they're testing take >10s)"""
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

    def test_get_frametext_from_files(self):
        """Test get_frametext_from_files
            Each list within this list is all of the frames from one pcap
        """
        actual_frame_dict = get_frametext_from_files(self.filenames)
        expected_frame_dict = {
            'tests/files/in_order_packets.pcap': {
                'frames': [
                    '0000  88 15 44 ab bf dd 24 77 03 51 13 44 08 00 45 00\n'
                    '0010  00 38 0b 5d 00 00 40 11 c7 98 0a 30 12 90 0a 80\n'
                    '0020  80 80 ea 62 00 35 00 24 a4 92 9b 13 01 00 00 01\n'
                    '0030  00 00 00 00 00 00 06 61 6d 61 7a 6f 6e 03 63 6f\n'
                    '0040  6d 00 00 01 00 01                              \n',
                    '0000  88 15 44 ab bf dd 24 77 03 51 13 44 08 00 45 00\n'
                    '0010  00 54 64 f3 40 00 40 01 a8 e6 0a 30 12 90 08 08\n'
                    '0020  08 08 08 00 e3 4e 61 22 00 01 c0 30 ab 5b 00 00\n'
                    '0030  00 00 7f 2e 0a 00 00 00 00 00 10 11 12 13 14 15\n'
                    '0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25\n'
                    '0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35\n'
                    '0060  36 37                                          \n'
                ],
                'timestamps': ['1537945792.655360000', '1537945792.720895000']
            },
            'tests/files/test.pcap': {
                'frames': [
                    '0000  24 77 03 51 13 44 88 15 44 ab bf dd 08 00 45 20\n'
                    '0010  00 54 2b bc 00 00 79 01 e8 fd 08 08 08 08 0a 30\n'
                    '0020  12 90 00 00 82 a5 63 11 00 01 f9 30 ab 5b 00 00\n'
                    '0030  00 00 a9 e8 0d 00 00 00 00 00 10 11 12 13 14 15\n'
                    '0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25\n'
                    '0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35\n'
                    '0060  36 37                                          \n'
                ],
                'timestamps': ['1537945792.667334000']
            }
        }

        self.assertDictEqual(actual_frame_dict, expected_frame_dict)


class TestSaveFile(unittest.TestCase):
    """Test save_file.py"""

    def setUp(self):
        """Setup env."""
        setup_testenv()
        self.options = {'strip-l2': False, 'strip-l3': False, 'pcapng': False}
        self.test_packet = "247703511344881544abbfdd0800452000542bbc00007901" \
                           "e8fd080808080a301290000082a563110001f930ab5b0000" \
                           "0000a9e80d0000000000101112131415161718191a1b1c1d" \
                           "1e1f202122232425262728292a2b2c2d2e2f303132333435" \
                           "3637"
        self.result_packet = \
            """0000  24 77 03 51 13 44 88 15 44 ab bf dd 08 00 45 20
0010  00 54 2b bc 00 00 79 01 e8 fd 08 08 08 08 0a 30
0020  12 90 00 00 82 a5 63 11 00 01 f9 30 ab 5b 00 00
0030  00 00 a9 e8 0d 00 00 00 00 00 10 11 12 13 14 15
0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
0060  36 37              \n"""

    def test_get_frame_len(self):
        expected_len = 28
        actual_len = get_frame_len(self.test_packet)
        self.assertEqual(expected_len, actual_len)

    def test_convert_to_pcaptext(self):
        """test the conversion of ASCII hexdump to text2pcap-readable"""
        actual = get_canonical_hex(self.test_packet)
        expected = self.result_packet
        self.assertEqual(expected, actual)

    def test_reorder_packets(self):
        """Reorder packets in tempfile inplace and compare with expected."""
        out_of_order = 'tests/files/out_of_order_packets.pcap'
        temp_out_of_order = 'tests/files/out_of_order_temp.pcap'
        in_order = 'tests/files/in_order_packets.pcap'

        shutil.copyfile(out_of_order, temp_out_of_order)
        self.assertTrue(filecmp.cmp(temp_out_of_order, out_of_order))
        reorder_packets(temp_out_of_order)

        self.assertTrue(filecmp.cmp(temp_out_of_order, in_order))
        os.remove(temp_out_of_order)

    def test_save_pcap(self):
        """test save_pacp."""
        pcap_dict = {self.result_packet: '1537945792.667334763'}
        save_pcap(pcap_dict=pcap_dict, name='test.pcap', options=self.options)
        self.assertTrue(filecmp.cmp('test.pcap', 'tests/files/test.pcap'))
        os.remove('test.pcap')

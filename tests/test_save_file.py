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
"""Test save_file.py."""

import unittest

from pcapgraph.save_file import convert_to_pcaptext
from pcapgraph import get_tshark_status


class TestSaveFile(unittest.TestCase):
    def setUp(self):
        """Make sure that tshark is in PATH."""
        # Add the wireshark folder to PATH for this shell.
        get_tshark_status()

    def test_convert_to_pcaptext(self):
        """test the conversion of ASCII hexdump to text2pcap-readable"""
        test_packet = "247703511344881544abbfdd0800452000542bbc00007901e8fd0" \
                      "80808080a301290000082a563110001f930ab5b00000000a9e80d" \
                      "0000000000101112131415161718191a1b1c1d1e1f20212223242" \
                      "5262728292a2b2c2d2e2f3031323334353637"
        result_packet = \
            """0000  24 77 03 51 13 44 88 15 44 ab bf dd 08 00 45 20
0010  00 54 2b bc 00 00 79 01 e8 fd 08 08 08 08 0a 30
0020  12 90 00 00 82 a5 63 11 00 01 f9 30 ab 5b 00 00
0030  00 00 a9 e8 0d 00 00 00 00 00 10 11 12 13 14 15
0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
0060  36 37              \n"""

        self.assertEqual(convert_to_pcaptext(test_packet), result_packet)
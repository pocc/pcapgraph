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
"""Test wireshark_io.py

Not implemented: verify_wireshark, get_wireshark_version
"""

import unittest
import tempfile
import subprocess as sp
import sys
import os
import filecmp

import psutil

from tests import setup_testenv
from pcapgraph.wireshark_io import abs_filepaths, convert_to_pcap, \
    decode_stdout, get_pcap_info, get_tshark_output, \
    open_in_wireshark, parse_filenames


class TestWiresharkIO(unittest.TestCase):
    """Test manipulate_frames"""

    def setUp(self):
        """set directory to project root."""
        setup_testenv()

    def test_abs_filepaths(self):
        """Test abs_filepaths: this dir and user dir expanison"""
        files = ['..', '~']
        absolute_filepaths = abs_filepaths(files)
        # Assert that files and returned absolute files have no common elements
        common_elems = set(files).intersection(set(absolute_filepaths))
        self.assertSetEqual(common_elems, set())

    def test_convert_to_pcap(self):
        """Test convert to pcap with tests/files pcaps

        in_order_packets.pcapng and ~.pcap should have the same packets.
        convert one to the other and verify whether result has the same hash
        as the existing .pcap file.
        """
        from_file = 'tests/files/in_order_packets.pcapng'
        target_file = 'tests/files/in_order_packets.pcap'
        with tempfile.NamedTemporaryFile() as temp_file:
            convert_to_pcap(from_file, temp_file.name)
            self.assertTrue(filecmp.cmp(target_file, temp_file.name))

    def test_decode_stdout(self):
        """python -V should equal sys.version. decode_stdout can test this"""
        python_exe = sys.executable
        python_stdout = sp.Popen([python_exe, '-V'], stdout=sp.PIPE)
        python_stdout_version = decode_stdout(python_stdout)
        python_sys_version = 'Python ' + sys.version.split(' ')[0]
        self.assertEqual(python_stdout_version, python_sys_version)

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

    def test_tshark_output(self):
        """Test tshark_output.py w expected output from in_order_packets.py"""
        input_file = os.getcwd() + '/tests/files/in_order_packets.pcap'
        expected_output = """1   0.000000 10.48.18.144 → 10.128.128.128 DN\
S 70 Standard query 0x9b13 A amazon.com\n    2   0.065535 10.48.18.144 → \
8.8.8.8      ICMP 98 Echo (ping) request  id=0x6122, seq=1/256, ttl=64"""
        actual_output = get_tshark_output(input_file)
        self.assertEqual(expected_output, actual_output)

    def test_open_in_wireshark(self):
        """test open_in_wireshark. process.open_files() doesn't exist?

        Open 2 files and verify that the process name is 'sh' that Popen calls
        """
        files = ['tests/files/empty.pcap', 'tests/files/in_order_packets.pcap']
        pids = open_in_wireshark(files)
        process_names = []
        for pid in pids:
            process = psutil.Process(pid)
            process_names.append(process.name())
        self.assertEqual(process_names, ['sh', 'sh'])

        for pid in pids:
            psutil.Process(pid).terminate()

    def test_parse_filenames(self):
        """Test parsing filenames. Should not include the .pickle in dir."""
        current_dir = os.getcwd()
        expected_files = \
            [current_dir + '/test.pcapng',
             current_dir + '/l3_stripped_intersect.pcap',
             current_dir + '/in_order_packets.pcap',
             current_dir + '/in_order_packets.pcapng',
             current_dir + '/empty.pcap',
             current_dir + '/l2_stripped_intersect.pcap',
             current_dir + '/out_of_order_packets.pcap',
             current_dir + '/test.pcap',
             current_dir + '/examples/simul1.pcapng']

        files_and_dirs = ['tests/files', 'examples/simul1.pcapng']
        actual_files = parse_filenames(files_and_dirs)

        self.assertListEqual(actual_files, expected_files)

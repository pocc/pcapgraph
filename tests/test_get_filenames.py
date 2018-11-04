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
"""Test get_filenames.py."""

import unittest

import pcapgraph.get_filenames as gf
from tests import setup_testenv, DEFAULT_CLI_ARGS


class TestGetFilenames(unittest.TestCase):
    """Test get_filenames.py."""
    def setUp(self):
        """Set up vars."""
        setup_testenv()
        self.args = DEFAULT_CLI_ARGS

    def test_parse_cli_args(self):
        """Test parse_cli_args."""
        self.args['--version'] = True
        # Version should exit.
        with self.assertRaises(SystemExit):
            gf.parse_cli_args(self.args)
        self.args['--version'] = False

        # directory and file should be properly detected as such and parsed.
        self.args['<file>'] = ['tests/files/test.pcap', 'tests/files/test_dir']
        expected_results = [
            'tests/files/test_dir/test_dir.pcap', 'tests/files/test.pcap'
        ]
        self.assertEqual(expected_results, gf.parse_cli_args(self.args))

    def test_get_filenames_from_directories(self):
        """Test get_filenames_from_directories"""
        directories = ['tests/files',
                       'tests/files/test_dir']
        pcap_filenames = sorted(gf.get_filenames_from_directories(directories))
        expected_result = ['tests/files/empty.pcap',
                           'tests/files/in_order_packets.pcap',
                           'tests/files/out_of_order_packets.pcap',
                           'tests/files/test.pcap',
                           'tests/files/test.pcapng',
                           'tests/files/test_dir/test_dir.pcap']
        self.assertEqual(expected_result, pcap_filenames)

    def test_get_filenames(self):
        """Test get_filenames.

        If an incorrect file is entered, expected behavior is to exit.
        """
        filenames = ['tests/files/test.txt',
                     'tests/files/test.pcap',
                     'tests/files/test.pcapng']
        packet_captures = []
        for filename in filenames:
            try:
                packet_captures += gf.get_filenames([filename])
            # For one text file that is expected to error out.
            except SystemExit:
                pass

        expected_result = ['tests/files/test.pcap',
                           'tests/files/test.pcapng']
        self.assertEqual(expected_result, packet_captures)

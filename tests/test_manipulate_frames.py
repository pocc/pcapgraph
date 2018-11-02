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

from tests import setup_testenv, DEFAULT_CLI_ARGS
from pcapgraph.manipulate_frames import *


class TestManipulateFrames(unittest.TestCase):
    """Test manipulate_framse"""

    def setUp(self):
        """set directory to project root."""
        setup_testenv()
        self.args = DEFAULT_CLI_ARGS

    def test_get_pcap_dict(self):
        raise NotImplemented

    def test_parse_pcaps(self):
        raise NotImplemented

    def test_get_flat_frame_dict(self):
        raise NotImplemented

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

    def test_anonymous_pcap_name(self):
        raise NotImplemented

    def test_decode_stdout(self):
        raise NotImplemented

    def test_get_packet_count(self):
        raise NotImplemented


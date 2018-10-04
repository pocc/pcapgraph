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
"""Test pcap_math.py."""

import unittest
import filecmp
import os

from pcap_algebra.pcap_math import union_pcap
from pcap_algebra.pcap_math import intersect_pcap
from pcap_algebra.pcap_math import bounded_intersect_pcap
from pcap_algebra.pcap_math import difference_pcap
from pcap_algebra.pcap_math import convert_to_pcaptext


class TestPcapMath(unittest.TestCase):
    def test_union_pcap(self):
        """Test union_pcap using the pcaps in examples."""
        # This will generate union.pcap in tests/
        union_pcap('../examples/simul1.pcap', '../examples/simul2.pcap',
                   '../examples/simul3.pcap')
        # The generated file should be the same as examples/union.pcap
        self.assertTrue(filecmp.cmp('union.pcap', '../examples/union.pcap'))
        os.remove('union.pcap')

    def test_intersect_pcap(self):
        """Test union_pcap using the pcaps in examples."""
        # This will generate intersect.pcap in tests/
        intersect_pcap('../examples/simul1.pcap', '../examples/simul2.pcap',
                       '../examples/simul3.pcap')
        # The generated file should be the same as examples/union.pcap
        self.assertTrue(filecmp.cmp('intersect.pcap',
                                    '../examples/intersect.pcap'))
        os.remove('intersect.pcap')

    def test_bounded_interface_pcap(self):
        """~"""

    def test_difference_pcap(self):
        """Test the difference_pcap method with multiple pcaps."""
        # This will generate difference.pcap in tests/
        difference_pcap('../examples/simul1.pcap', '../examples/simul2.pcap',
                        '../examples/simul3.pcap')
        # The generated file should be the same as examples/union.pcap
        self.assertTrue(filecmp.cmp('difference.pcap',
                                    '../examples/difference.pcap'))
        os.remove('difference.pcap')

    def test_convert_to_pcaptext(self):
        """~"""

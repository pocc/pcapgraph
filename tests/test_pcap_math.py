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

from pcapgraph.pcap_math import union_pcap
from pcapgraph.pcap_math import intersect_pcap
from pcapgraph.pcap_math import difference_pcap
from pcapgraph.pcap_math import bounded_intersect_pcap
from pcapgraph.pcap_math import get_minmax_common_frames
from pcapgraph import get_tshark_status


class TestPcapMath(unittest.TestCase):
    def setUp(self):
        """Make sure that tshark is in PATH."""
        # Add the wireshark folder to PATH for this shell.
        get_tshark_status()

    def test_union_pcap(self):
        """Test union_pcap using the pcaps in examples."""
        # This will generate union.pcap in tests/
        union_pcap('../examples/simul1.pcap',
                   '../examples/simul2.pcap',
                   '../examples/simul3.pcap')
        # The generated file should be the same as examples/union.pcap
        self.assertTrue(filecmp.cmp('union.pcap', '../examples/union.pcap'))
        os.remove('union.pcap')

    def test_intersect_pcap(self):
        """Test union_pcap using the pcaps in examples."""
        # This will generate intersect.pcap in tests/
        intersect_pcap('../examples/simul1.pcap',
                       '../examples/simul2.pcap',
                       '../examples/simul3.pcap')
        # The generated file should be the same as examples/union.pcap
        self.assertTrue(filecmp.cmp('intersect.pcap',
                                    '../examples/intersect.pcap'))
        # examples/intersect.pcap is from all 3 simul pcaps, so using
        # 2 of 3 should fail as the generated intersection will be different.
        intersect_pcap('../examples/simul1.pcap',
                       '../examples/simul2.pcap')
        self.assertFalse(filecmp.cmp('intersect.pcap',
                                     '../examples/intersect.pcap'))
        os.remove('intersect.pcap')

    def test_difference_pcap(self):
        """Test the difference_pcap method with multiple pcaps."""
        # This will generate difference.pcap in tests/
        difference_pcap('../examples/simul1.pcap',
                        '../examples/simul2.pcap',
                        '../examples/simul3.pcap')
        # The generated file should be the same as examples/union.pcap
        self.assertTrue(filecmp.cmp('difference.pcap',
                                    '../examples/diff_simul1-simul2.pcap'))
        os.remove('difference.pcap')

    def test_get_minmax_common_frames(self):
        """Test get_minmax_common frames."""
        pass
        #get_minmax_common_frames(['../examples/simul1.pcap',
        #                          '../examples/simul2.pcap',
        #                          '../examples/simul3.pcap'])

    def test_bounded_interface_pcap(self):
        """Test the bounded_interface_pcap using pcaps in examples."""
        bounded_intersect_pcap('../examples/simul1.pcap',
                               '../examples/simul2.pcap',
                               '../examples/simul3.pcap')
        # All 3 simul time-bound intersections should be the same and also
        # equal to the intersect.pcap. This is due to the traffic being the
        # same and there being no infixed traffic from other sources.
        self.assertTrue(filecmp.cmp('bounded_intersect-simul1.pcap',
                                    '../examples/intersect.pcap'))
        self.assertTrue(filecmp.cmp('bounded_intersect-simul2.pcap',
                                    '../examples/intersect.pcap'))
        self.assertTrue(filecmp.cmp('bounded_intersect-simul3.pcap',
                                    '../examples/intersect.pcap'))
        os.remove('bounded_intersect-simul1.pcap')
        os.remove('bounded_intersect-simul2.pcap')
        os.remove('bounded_intersect-simul3.pcap')

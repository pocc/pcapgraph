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
import io
import re
from contextlib import redirect_stdout

from pcapgraph.pcap_math import PcapMath
from tests import setup_testenv, DEFAULT_CLI_ARGS, EXPECTED_UNION_STDOUT


class TestPcapMath(unittest.TestCase):
    """Test pcap_math.py. Expected to be run from project root."""

    def setUp(self):
        """Make sure that tshark is in PATH."""
        setup_testenv()
        self.options = {'strip-l2': False, 'strip-l3': False, 'pcapng': False}
        filenames = [
            'examples/simul1.pcap',
            'examples/simul2.pcap',
            'examples/simul3.pcap'
        ]
        self.set_obj = PcapMath(filenames, self.options)

    def test_exclude_empty(self):
        """Verify --exclude-empty option. Relevant for pcap differences.

        A difference of a file and itself should be an empty packet capture.
        If we do not save that packet capture and remove it from the filelist,
        it should not appear in the return filelist.
        """
        args = DEFAULT_CLI_ARGS
        args['--exclude-empty'] = True
        args['--difference'] = True
        args['--union'] = False  # Required to avoid unexpected pytest behavior
        # Have to specify filename in 2 ways because filename is key in dict.
        filenames = [
            'examples/simul1.pcap', '../pcapgraph/examples/simul1.pcap'
        ]
        exclude_set_obj = PcapMath(filenames, self.options)
        excluded_filenames = exclude_set_obj.parse_set_args(args)
        self.assertEqual(filenames, excluded_filenames)

    def test_union_pcap(self):
        """Test union_pcap using the pcaps in examples."""
        # These 4 lines will save generated_stdout from union()
        f_stream = io.StringIO()
        with redirect_stdout(f_stream):
            self.set_obj.union_pcap()
        generated_stdout = f_stream.getvalue()
        # Remove all whitespace at end of lines to match expected
        generated_stdout = re.sub(r' +$', '', generated_stdout, flags=re.M)

        # Tests print_10_most_common_frames
        self.assertEqual(EXPECTED_UNION_STDOUT, generated_stdout)
        self.assertTrue(
            filecmp.cmp('union.pcap', 'examples/set_ops/union.pcap'))
        os.remove('union.pcap')

    def test_intersect_pcap(self):
        """Test union_pcap using the pcaps in examples."""
        # This will generate intersect.pcap in tests/
        self.set_obj.intersect_pcap()
        # The generated file should be the same as examples/union.pcap
        self.assertTrue(
            filecmp.cmp('intersect.pcap', 'examples/set_ops/intersect.pcap'))
        # examples/intersect.pcap is from all 3 simul pcaps, so using
        # 2 of 3 should fail as the generated intersection will be different.
        two_thirds = PcapMath(['examples/simul1.pcap', 'examples/simul2.pcap'],
                              options=self.options)
        two_thirds.intersect_pcap()
        self.assertFalse(
            filecmp.cmp('intersect.pcap', 'examples/set_ops/intersect.pcap'))
        os.remove('intersect.pcap')

    def test_difference_pcap(self):
        """Test the difference_pcap method with multiple pcaps."""
        diff1and3 = PcapMath(['examples/simul1.pcap', 'examples/simul3.pcap'],
                             self.options)
        diff_filename = diff1and3.difference_pcap()
        self.assertTrue(filecmp.cmp(
            diff_filename,
            'examples/set_ops/diff_simul1-simul3.pcap'))
        os.remove('diff_simul1.pcap')

    def test_symmetric_difference(self):
        """Test the symmetric difference method with muliple pcaps."""
        self.set_obj.symmetric_difference_pcap()
        # The generated file should be the same as examples/union.pcap
        self.assertTrue(
            filecmp.cmp('symdiff_simul1.pcap',
                        'examples/set_ops/symdiff_simul1.pcap'))
        self.assertTrue(
            filecmp.cmp('symdiff_simul3.pcap',
                        'examples/set_ops/symdiff_simul3.pcap'))
        os.remove('symdiff_simul1.pcap')
        os.remove('symdiff_simul2.pcap')
        os.remove('symdiff_simul3.pcap')

    def test_get_minmax_common_frames(self):
        """Test get_minmax_common against expected frame outputs"""
        min_frame = '0000  88 15 44 ab bf dd 24 77 03 51 13 44 08 00 45 00\n' \
                    '0010  00 54 7b af 40 00 40 01 92 2a 0a 30 12 90 08 08\n' \
                    '0020  08 08 08 00 ae 46 62 8b 00 01 e8 30 ab 5b 00 00\n' \
                    '0030  00 00 88 cd 0c 00 00 00 00 00 10 11 12 13 14 15\n' \
                    '0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25\n' \
                    '0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35\n' \
                    '0060  36 37                                          \n'

        max_frame = '0000  24 77 03 51 13 44 88 15 44 ab bf dd 08 00 45 20\n' \
                    '0010  00 54 2b bc 00 00 79 01 e8 fd 08 08 08 08 0a 30\n' \
                    '0020  12 90 00 00 82 a5 63 11 00 01 f9 30 ab 5b 00 00\n' \
                    '0030  00 00 a9 e8 0d 00 00 00 00 00 10 11 12 13 14 15\n' \
                    '0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25\n' \
                    '0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35\n' \
                    '0060  36 37                                          \n'

        actual_min_frame, actual_max_frame = \
            self.set_obj.get_minmax_common_frames()
        self.assertEqual(min_frame, actual_min_frame)
        self.assertEqual(max_frame, actual_max_frame)

    def test_bounded_intersect_pcap(self):
        """Test the bounded_intersect_pcap using pcaps in examples.

        This should also test get_bounded_pcaps at the same time.

        All 3 simul time-bound intersections should be the same and also
        equal to the intersect.pcap. This is due to the traffic being the
        same and there being no infixed traffic from other sources.
        """
        self.set_obj.bounded_intersect_pcap()
        self.assertTrue(
            filecmp.cmp('bounded_intersect-simul1.pcap',
                        'examples/set_ops/intersect.pcap'))
        self.assertTrue(
            filecmp.cmp('bounded_intersect-simul2.pcap',
                        'examples/set_ops/intersect.pcap'))
        self.assertTrue(
            filecmp.cmp('bounded_intersect-simul3.pcap',
                        'examples/set_ops/intersect.pcap'))
        os.remove('bounded_intersect-simul1.pcap')
        os.remove('bounded_intersect-simul2.pcap')
        os.remove('bounded_intersect-simul3.pcap')

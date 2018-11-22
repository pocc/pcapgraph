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
import tempfile

from pcapgraph.pcap_math import PcapMath
import pcapgraph.manipulate_framebytes as mfb
import pcapgraph.save_file as sf
from tests import setup_testenv, DEFAULT_CLI_ARGS, EXPECTED_UNION_STDOUT


class TestPcapMath(unittest.TestCase):
    """Test pcap_math.py. Expected to be run from project root."""

    def setUp(self):
        """Make sure that tshark is in PATH."""
        setup_testenv()
        self.options = {'strip-l2': False, 'strip-l3': False, 'pcapng': False}
        filenames = [
            'examples/simul1.pcapng',
            'examples/simul2.pcapng',
            'examples/simul3.pcapng'
        ]
        self.set_obj = PcapMath(filenames, self.options)

    def test_exclude_empty(self):
        """Verify --exclude-empty option. Relevant for pcap differences.

        A difference of a file and itself should be an empty packet capture.
        If we do not save that packet capture and remove it from the filelist,
        it should not appear in the return filelist.
        """
        args = dict(DEFAULT_CLI_ARGS)
        args['--exclude-empty'] = True
        args['--difference'] = True
        # Have to specify filename in 2 ways because filename is key in dict.
        filenames = [
            'examples/simul1.pcapng', '../pcapgraph/examples/simul1.pcapng'
        ]
        exclude_set_obj = PcapMath(filenames, self.options)
        excluded_pcap_frames = exclude_set_obj.parse_set_args(args)
        excluded_filenames = list(excluded_pcap_frames)
        self.assertEqual(filenames, excluded_filenames)

    def skip_test_10_most_common_frames(self):
        """Test 10 most common frames. Skip as it takes 5s with stdout use."""
        # These 4 lines will save generated_stdout from union()
        f_stream = io.StringIO()
        with redirect_stdout(f_stream):
            mfb.print_10_most_common_frames(self.set_obj.frame_list)
        generated_stdout = f_stream.getvalue()
        # Remove all whitespace at end of lines to match expected
        generated_stdout = re.sub(r' +$', '', generated_stdout, flags=re.M)
        # Tests print_10_most_common_frames
        self.assertEqual(EXPECTED_UNION_STDOUT, generated_stdout)

    def test_union_pcap(self):
        """Test union_pcap using the pcaps in examples."""
        pcap_frame_list = self.set_obj.union_pcap()
        frame_list = list(pcap_frame_list)
        timestamp_list = list(pcap_frame_list.values())
        with tempfile.NamedTemporaryFile() as temp_file:
            mfb.write_file_bytes(temp_file.name, frame_list, timestamp_list)
            self.assertTrue(
                filecmp.cmp(temp_file.name, 'examples/set_ops/union.pcap'))

    def test_intersect_pcap(self):
        """Test union_pcap using the pcaps in examples."""
        # Dicts of form {<frame>: <timestamp>, ...}
        intersect_frame_dict = self.set_obj.intersect_pcap()
        # The generated file should be the same as examples/union.pcap
        with tempfile.NamedTemporaryFile() as temp_file:
            mfb.write_file_bytes(temp_file.name,
                                 list(intersect_frame_dict),  # frames
                                 list(intersect_frame_dict.values()))  # ts
            self.assertTrue(
                filecmp.cmp(temp_file.name, 'examples/set_ops/intersect.pcap'))
        # examples/intersect.pcap is from all 3 simul pcaps, so using
        # 2 of 3 should fail as the generated intersection will be different.
        two_thirds = PcapMath(['examples/simul1.pcapng',
                               'examples/simul2.pcapng'],
                              options=self.options)
        two_thirds_frame_dict = two_thirds.intersect_pcap()
        with tempfile.NamedTemporaryFile() as temp_file:
            mfb.write_file_bytes(temp_file.name,
                                 list(two_thirds_frame_dict),  # frames
                                 list(two_thirds_frame_dict.values()))  # ts
            self.assertFalse(
                filecmp.cmp(temp_file.name, 'examples/set_ops/intersect.pcap'))

    def test_strip_l2_intersect(self):
        """test strip l2 intersect

        In the produced intersect, we should see only packets of type raw-ip.
        """
        args = dict(DEFAULT_CLI_ARGS)
        args['--output'] = ['pcap']
        args['--intersect'] = True
        filenames = [
            'examples/simul1.pcapng',
            'examples/simul2.pcapng',
            'examples/simul3.pcapng'
        ]
        options = {'strip-l2': True, 'strip-l3': False, 'pcapng': False}
        pcap_math = PcapMath(filenames, options)
        pcaps_frame_dict = pcap_math.parse_set_args(args)
        frame_timestamp_dict = {}
        for pcap in filenames:
            new_dict = {
                k: v for k, v in zip(pcaps_frame_dict[pcap]['frames'],
                                     pcaps_frame_dict[pcap]['timestamps'])
            }
            frame_timestamp_dict = {**frame_timestamp_dict, **new_dict}
        sf.save_pcap(frame_timestamp_dict, 'intersect.pcap', options)
        self.assertFalse(filecmp.cmp('intersect.pcap',
                                     'tests/files/l2_stripped_intersect.pcap'))
        os.remove('intersect.pcap')

    def test_strip_l3_intersect(self):
        """test strip l3 intersect

        In the produced intersect, we should see only packets that are not
        distinguishable at l3.
        """
        args = dict(DEFAULT_CLI_ARGS)
        args['--output'] = ['pcap']
        args['--intersect'] = True
        filenames = [
            'examples/simul1.pcapng',
            'examples/simul2.pcapng',
            'examples/simul3.pcapng'
        ]
        options = {'strip-l2': False, 'strip-l3': True, 'pcapng': False}
        pcap_math = PcapMath(filenames, options)
        pcaps_frame_dict = pcap_math.parse_set_args(args)
        frame_timestamp_dict = {}
        for pcap in filenames:
            new_dict = {
                k: v for k, v in zip(pcaps_frame_dict[pcap]['frames'],
                                     pcaps_frame_dict[pcap]['timestamps'])
            }
            frame_timestamp_dict = {**frame_timestamp_dict, **new_dict}
        sf.save_pcap(frame_timestamp_dict, 'intersect.pcap', options)
        self.assertFalse(filecmp.cmp('intersect.pcap',
                                     'tests/files/l3_stripped_intersect.pcap'))
        os.remove('intersect.pcap')

    def test_difference_pcap(self):
        """Test the difference_pcap method with multiple pcaps."""
        diff1and3 = PcapMath(['examples/simul1.pcapng',
                              'examples/simul3.pcapng'],
                             self.options)
        diff_pcap_frames = diff1and3.difference_pcap()
        expected_diff_file = 'examples/set_ops/diff_simul1-simul3.pcap'
        frame_list = list(diff_pcap_frames)
        timestamp_list = list(diff_pcap_frames.values())
        with tempfile.NamedTemporaryFile() as temp_file:
            mfb.write_file_bytes(temp_file.name, frame_list, timestamp_list)
            self.assertTrue(filecmp.cmp(temp_file.name, expected_diff_file))

    def test_symmetric_difference(self):
        """Test the symmetric difference method with muliple pcaps."""
        sym_diff_pcap_frames = self.set_obj.symmetric_difference_pcap()
        # The generated file should be the same as examples/union.pcap
        for index, pcap in enumerate(sym_diff_pcap_frames):
            frame_list = list(sym_diff_pcap_frames[pcap])
            ts_list = list(sym_diff_pcap_frames[pcap].values())
            expected_symdiff_file = \
                'examples/set_ops/symdiff_simul' + str(index + 1) + '.pcap'

            with tempfile.NamedTemporaryFile() as temp_file:
                mfb.write_file_bytes(temp_file.name, frame_list, ts_list)
                if index != 1:  # Symdiff 2 is expected to be empty
                    self.assertTrue(
                       filecmp.cmp(temp_file.name, expected_symdiff_file))

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
        bounded_pcap_frames = self.set_obj.bounded_intersect_pcap()
        for index, pcap in enumerate(bounded_pcap_frames):
            frame_list = list(bounded_pcap_frames[pcap])
            ts_list = list(bounded_pcap_frames[pcap].values())
            expected_symdiff_file = 'examples/set_ops/intersect.pcap'

            with tempfile.NamedTemporaryFile() as temp_file:
                mfb.write_file_bytes(temp_file.name, frame_list, ts_list)
                self.assertTrue(
                    filecmp.cmp(temp_file.name, expected_symdiff_file))

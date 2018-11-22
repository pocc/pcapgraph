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
import io
import re
from contextlib import redirect_stdout
import tempfile

from pcapgraph.pcap_math import PcapMath
import pcapgraph.manipulate_framebytes as mfb
from tests import setup_testenv, DEFAULT_CLI_ARGS, EXPECTED_UNION_STDOUT


class TestPcapMath(unittest.TestCase):
    """Test pcap_math.py. Expected to be run from project root."""

    def setUp(self):
        """Make sure that tshark is in PATH."""
        setup_testenv()
        self.options = {'strip-l2': False, 'strip-l3': False, 'pcapng': False}
        self.filenames = [
            'examples/simul1.pcapng', 'examples/simul2.pcapng',
            'examples/simul3.pcapng'
        ]
        self.set_obj = PcapMath(self.filenames, self.options)

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
            mfb.write_file_bytes(temp_file.name, frame_list, timestamp_list, 1)
            self.assertTrue(
                filecmp.cmp(temp_file.name, 'examples/set_ops/union.pcap'))

    def test_intersect_pcap(self):
        """Test union_pcap using the pcaps in examples."""
        # Dicts of form {<frame>: <timestamp>, ...}
        intersect_frame_dict = self.set_obj.intersect_pcap()
        # The generated file should be the same as examples/union.pcap
        with tempfile.NamedTemporaryFile() as temp_file:
            mfb.write_file_bytes(
                temp_file.name,
                list(intersect_frame_dict),  # frames
                list(intersect_frame_dict.values()),  # ts
                1)
            self.assertTrue(
                filecmp.cmp(temp_file.name, 'examples/set_ops/intersect.pcap'))
        # examples/intersect.pcap is from all 3 simul pcaps, so using
        # 2 of 3 should fail as the generated intersection will be different.
        two_thirds = PcapMath(
            ['examples/simul1.pcapng', 'examples/simul2.pcapng'],
            options=self.options)
        two_thirds_frame_dict = two_thirds.intersect_pcap()
        with tempfile.NamedTemporaryFile() as temp_file:
            mfb.write_file_bytes(
                temp_file.name,
                list(two_thirds_frame_dict),  # frames
                list(two_thirds_frame_dict.values()),  # ts
                1)
            self.assertFalse(
                filecmp.cmp(temp_file.name, 'examples/set_ops/intersect.pcap'))

    def test_strip_l2_intersect(self):
        """test strip l2 and l3 intersect

        One function for both because setup has so much in common.
        In the produced intersect, we should see only packets of type raw-ip.
        """
        strip_l2_opts = {'strip-l2': True, 'strip-l3': False, 'pcapng': False}
        strip_l2_obj = PcapMath(self.filenames, strip_l2_opts)
        intersect_frame_dict = strip_l2_obj.intersect_pcap()
        frame_list = list(intersect_frame_dict)
        ts_list = list(intersect_frame_dict.values())

        expected_l2_stripped = 'tests/files/l2_stripped_intersect.pcap'
        with tempfile.NamedTemporaryFile() as temp_file:
            mfb.write_file_bytes(temp_file.name, frame_list, ts_list, 101)
            self.assertTrue(filecmp.cmp(temp_file.name, expected_l2_stripped))

    def test_strip_l3_intersect(self):
        """test strip l3 intersect

        In the produced intersect, we should see only packets that are not
        distinguishable at l3.
        """
        strip_l3_opts = {'strip-l2': False, 'strip-l3': True, 'pcapng': False}
        strip_l3_obj = PcapMath(self.filenames, strip_l3_opts)
        intersect_frame_dict = strip_l3_obj.intersect_pcap()
        frame_list = list(intersect_frame_dict)
        ts_list = list(intersect_frame_dict.values())

        expected_l3_stripped = 'tests/files/l3_stripped_intersect.pcap'
        with tempfile.NamedTemporaryFile() as temp_file:
            mfb.write_file_bytes(temp_file.name, frame_list, ts_list, 101)
            self.assertTrue(filecmp.cmp(temp_file.name, expected_l3_stripped))

    def test_difference_pcap(self):
        """Test the difference_pcap method with multiple pcaps."""
        diff1and3 = PcapMath(
            ['examples/simul1.pcapng', 'examples/simul3.pcapng'], self.options)
        diff_pcap_frames = diff1and3.difference_pcap()
        expected_diff_file = 'examples/set_ops/diff_simul1-simul3.pcap'
        frame_list = list(diff_pcap_frames)
        timestamp_list = list(diff_pcap_frames.values())
        with tempfile.NamedTemporaryFile() as temp_file:
            mfb.write_file_bytes(temp_file.name, frame_list, timestamp_list, 1)
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
                mfb.write_file_bytes(temp_file.name, frame_list, ts_list, 1)
                if index != 1:  # Symdiff 2 is expected to be empty
                    self.assertTrue(
                        filecmp.cmp(temp_file.name, expected_symdiff_file))

    def test_get_minmax_common_frames(self):
        """Test get_minmax_common against expected frame outputs"""
        min_frame = b'\x88\x15D\xab\xbf\xdd$w\x03Q\x13D\x08\x00E\x00\x00T{\xaf@\x00@\x01\x92*\n0\x12\x90\x08\x08\x08\x08\x08\x00\xaeFb\x8b\x00\x01\xe80\xab[\x00\x00\x00\x00\x88\xcd\x0c\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567'  # noqa: E501 pylint: disable=C0301
        max_frame = b'$w\x03Q\x13D\x88\x15D\xab\xbf\xdd\x08\x00E \x00T+\xbc\x00\x00y\x01\xe8\xfd\x08\x08\x08\x08\n0\x12\x90\x00\x00\x82\xa5c\x11\x00\x01\xf90\xab[\x00\x00\x00\x00\xa9\xe8\r\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567'  # noqa: E501 pylint: disable=C0301

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
        for pcap in bounded_pcap_frames:
            frame_list = list(bounded_pcap_frames[pcap])
            ts_list = list(bounded_pcap_frames[pcap].values())
            expected_symdiff_file = 'examples/set_ops/intersect.pcap'

            with tempfile.NamedTemporaryFile() as temp_file:
                mfb.write_file_bytes(temp_file.name, frame_list, ts_list, 1)
                self.assertTrue(
                    filecmp.cmp(temp_file.name, expected_symdiff_file))

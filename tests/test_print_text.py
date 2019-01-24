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
"""Test print_text.py"""
import unittest

from pcapgraph.print_text import output_text


class TestPrintText(unittest.TestCase):
    """Test pcap_math.py. Expected to be run from project root."""
    def test_output_text(self):
        """Testing make_text_not_war."""
        pcap_times = {
            'in_order_packets': {
                'pcap_start': 1537945792.65536,
                'pcap_end': 1537945792.720895
            },
            'out_of_order_packets': {
                'pcap_start': 1537945792.720895,
                'pcap_end': 1537945792.65536
            },
            'test': {
                'pcap_start': 1537945792.667334,
                'pcap_end': 1537945792.667334
            }
        }

        expected_result = "\nPCAP NAME           YEAR  DATE 0  DATE $     TIME 0    TIME $       UTC 0              UTC $\nin_order_packets    2018  Sep-26  Sep-26     00:09:52  00:09:52     1537945792.65536   1537945792.720895 \nout_of_order_pack   2018  Sep-26  Sep-26     00:09:52  00:09:52     1537945792.720895  1537945792.65536  \ntest                2018  Sep-26  Sep-26     00:09:52  00:09:52     1537945792.667334  1537945792.667334 "  # noqa: E501 pylint: disable=C0301
        actual_result = output_text(pcap_times)
        self.assertEqual(expected_result, actual_result)

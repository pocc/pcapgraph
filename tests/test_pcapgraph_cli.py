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
"""Test pcapgraph_cli.py

Not tested: from pcapgraph.pcapgraph_cli import check_args, get_docstring, \
    get_output_options, get_selected_keys, get_set_operations, \
    get_strip_options, init_cli, print_version, requires_set_operations
"""
import unittest

import tests


class TestPcapgraphCli(unittest.TestCase):
    """Test draw_graph"""

    def setUp(self):
        """set directory to project root."""
        tests.setup_testenv()

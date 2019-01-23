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
"""Parse options from docopt dict."""
import re


def remove_rst_signals(docstring):
    """Remove ReStructuredText signals so docopt parses correctly."""
    return re.sub(r' *:: *\n\n|`|\*', '', docstring)


def get_strip_options(args):
    """Get --strip-l2 and --strip-l3 options"""
    strip_option_list = ['--strip-l2', '--strip-l3']
    return get_selected_keys(args, strip_option_list)


def get_output_options(args):
    """Return output options from input args if they are user selected."""
    output_option_list = ['--anonymize', '--show-packets', '--exclude-empty',
                          '--wireshark', '--plot']
    return get_selected_keys(args, output_option_list)


def get_selected_keys(args, keys):
    """If the key in the dict's value is true (selected), return the key."""
    selected_keys = []
    for key in keys:
        if args[key]:
            selected_keys.append(key)

    return selected_keys

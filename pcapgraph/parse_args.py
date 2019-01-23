# -*- coding: utf-8 -*-
# Copyright 2019 Ross Jacobs All Rights Reserved.
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
import sys

from . import __version__


def remove_rst_signals(docstring):
    """Remove ReStructuredText signals so docopt parses correctly."""
    return re.sub(r' *:: *\n\n|`|\*', '', docstring)


def print_version():
    """Print versions and exit."""
    print('pcapgraph', __version__)
    print('python', sys.version)
    sys.exit()


def check_args(args):
    """Verify args are valid."""
    has_set_ops = bool(get_set_operations(args))
    pcap_out = 'pcap' in args['--output'] or 'pcapng' in args['--output']
    if pcap_out and not has_set_ops:
        raise SyntaxError("\nERROR: --output pcap/pcapng needs "
                          "a set operation (-bdeiuy).")

    num_files = len(set(args['<file>']).union())
    if has_set_ops and num_files < 2:
        raise SyntaxError("\nERROR: Set operations require 2 or more different"
                          " packet captures (" + str(num_files) + " provided)")


def get_set_operations(args):
    """Return a list of all set operations specifiied"""
    set_operations = ['--intersection', '--union', '--difference',
                      '--symmetric-difference',
                      '--bounded-intersection', '--inverse-bounded']
    return get_selected_keys(args, set_operations)


def get_strip_options(args):
    """Get --strip-l2 and --strip-l3 options"""
    strip_option_list = ['--strip-l2', '--strip-l3']
    return get_selected_keys(args, strip_option_list)


def get_output_options(args):
    """Return output options from input args if they are user selected."""
    output_option_list = ['--anonymize', '--show-packets', '--exclude-empty',
                          '--wireshark', '--plot']
    return get_selected_keys(args, output_option_list)


def requires_set_operations(args):
    """Return whether the user's inputs require set operations to be used."""
    has_set_ops = bool(get_set_operations(args))
    return has_set_ops or args['--wireshark'] or args['--most-common-frames']


def requires_graph_operations(args):
    """Return whether the user's inputs require graph operations to be used."""


def get_selected_keys(args, keys):
    """If the key in the dict's value is true (selected), return the key."""
    selected_keys = []
    for key in keys:
        if args[key]:
            selected_keys.append(key)

    return selected_keys

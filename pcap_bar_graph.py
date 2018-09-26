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
"""PcapGraph

Usage:
  pcapgraph [-t | --text]  <file>...
  pcapgraph (-h | --help)
  pcapgraph (-v | --version)

Options:
  -h, --help            Show this screen.
  -v, --version         Show PcapGraph's version.
  -t, --text            Output results as markdown text instead of a graph

About:
  PcapGraph is used to determine whether
"""


import docopt

from parse_options import parse_cli_args, get_tshark_status, get_pcap_data
from draw_graph import draw_graph


def main():
    """Main function."""
    args = docopt.docopt(__doc__)
    filenames = parse_cli_args(args)
    get_tshark_status()  # PcapGraph requires tshark, so quit if it not installed
    pcap_dict = get_pcap_data(filenames)
    draw_graph(pcap_dict)


if __name__ == '__main__':
    main()
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
  pcapgraph <file>... [--format <format>] [-s] [-c]
  pcapgraph (-h | --help)
  pcapgraph (-v | --version)

Options:
  -c, --compare         Compare all files to the first file by ip.id and
                        ip.checksum to find the percent of packets that
                        match exactly. (See About for more details).
  -h, --help            Show this screen.
      --format <format> Output results as a file instead of a popup.
  -s, --show            Print the graph to the screen. If the format 'txt' is
                        selected, print to stdout instead of a text file.
  -v, --version         Show PcapGraph's version.

About:
  PcapGraph is used to determine when packet captures were taken using the
  wireshark filter 'frame.time_epoch' and creates a graph with those times.

  The first packet capture argument to pcapgraph will be used as a pivot to
  compare to other packet captures to compute fraction similar if -c is
  specified This is useful in determining overlap of pcaps; however,
  this is slow, so you may want to filter your pcaps before using this option.

  Comparison speed tests *per file* added (on a 6-year-old laptop):
    25K packets x 25K packets: 6s without -c, 12s with -c
    50K packets x 50K packets: 10s without -c, 20s with -c
    100K packets x 100K packets: 25s without -c, 50s with -c

Formats:
  Export formats are dependent on OS capabilities. Formats may include:
  eps, jpeg, jpg, pdf, pgf, png, ps, raw, rgba, svg, svgz, tif, tiff

  More information on format can be found in matplotlib's online documentation:
  https://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.savefig

"""
import docopt

from src.parse_options import parse_cli_args, get_tshark_status, get_pcap_data
from src.draw_graph import draw_graph


def main():
    """Main function."""
    args = docopt.docopt(__doc__)
    filenames = parse_cli_args(args)
    get_tshark_status()  # PcapGraph requires tshark, so quit if not installed
    pcap_dict = get_pcap_data(filenames, has_compare_pcaps=args['--compare'])
    draw_graph(pcap_dict, save_fmt=args['--format'], output_fmt=args['--show'])


if __name__ == '__main__':
    main()

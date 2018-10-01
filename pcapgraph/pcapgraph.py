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
  pcapgraph [-scV] [--format <format>] (--dir <dir>... | <file>...)
  pcapgraph (-g | --generate)
  pcapgraph (-h | --help)
  pcapgraph (-v | --version)

Options:
  <file>...             Any number of packet captures to analyze.
  -c, --compare         Compare all files to the first file by ip.id and
                        ip.checksum to find the percent of packets that
                        match exactly. (See About for more details).
  -d, --dir <dir>       Specify directories to add pcaps from.
                        Can be used multiple times.
  -g, --generate-pcaps  Generate 3 example packet captures (see Generation).
  -h, --help            Show this screen.
  -f, --format <format> Output results as a file instead of a popup.
  -v, --version         Show PcapGraph's version.
  -V, --verbose         Provide more context to what pcapgraph is doing.

About:
  PcapGraph is used to determine when packet captures were taken using the
  wireshark filter 'frame.time_epoch' and creates a graph with those times.

Input requirements
  Packet captures are required for this program to function. They can be
  specified either individually as files, as a directory, or any combination
  of the two. When -d/--dir is used, this program will search a directory for
  valid packet capture types (essentially any format that Wireshark supports).
  The following packet capture extensions are supported by Wireshark:
    .pcapng, .pcap, .cap, .dmp, .5vw, .TRC0, .TRC1, .enc,
    .trc, .fdc, .syc, .bfr, .tr1, .snoop

Generation of example packet captures
  Creates 3 packet captures with a ping + nslookup sent every second for 100s.
  The graph from these pcaps should match the png file in examples/. When
  using this command, you may need to use sudo depending on whether you have
  configured wireshark to allow unprivileged users to take packet captures.

  Pcap1 stars at 0s, Pcap2 starts at 20s, Pcap3 starts at 40s.
  Pcap1 should match Pcap1 100%, Pcap2 66%, and Pcap3 33% (with -c used).

Packet comparisons:
  The first packet capture argument to pcapgraph will be used as a pivot to
  compare to other packet captures to compute fraction similar if -c is
  specified This is useful in determining overlap of pcaps; however,
  this is slow, so you may want to filter your pcaps before using this option.

  Comparison speed tests *per file* added as param (on a 6-year-old laptop):
    25K packets x 25K packets: 12s with -c, 6s without
    50K packets x 50K packets: 20s with -c, 10s without
    100K packets x 100K packets: 50s with -c, 25s without

Formats:
  Export formats are dependent on OS capabilities. Formats may include:
  eps, jpeg, jpg, pdf, pgf, png, ps, raw, rgba, svg, svgz, tif, tiff

  More information on format can be found in matplotlib's online documentation:
  https://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.savefig

"""
import docopt

from .parse_options import parse_cli_args
from .parse_options import get_tshark_status
from .parse_options import get_pcap_dict
from .draw_graph import draw_graph


def run():
    """Main function."""
    args = docopt.docopt(__doc__)
    filenames = parse_cli_args(args)
    get_tshark_status()  # PcapGraph requires tshark, so quit if not installed
    pcap_dict = get_pcap_dict(filenames, args['--compare'], args['--verbose'])
    draw_graph(pcap_dict, save_fmt=args['--format'])


if __name__ == '__main__':
    run()

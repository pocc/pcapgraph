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
"""PcapGraph:
  Create bar graphs out of packet captures.

Usage:
  ‣ pcapgraph [-abdeisuvwx23] (<file>)... [--output <format>]...
  ‣ pcapgraph (-V | --version)
  ‣ pcapgraph (-h | --help)

Options:
  -a, --anonymize       Anonymize packet capture file names with fictional
                        place names and devices.
  -b, --bounded-intersection
                        Bounded intersection of packets (see Set Operations).
  -d, --difference      First packet capture minus packets in all succeeding
                        packet captures. (see Set Operations > difference).
  -e, --inverse-bounded
                        Shortcut for applying `-b` to a group of pcaps and then
                        subtracting the intersection from each.
  -h, --help            Show this screen.
  -i, --intersection    All packets that are shared by all packet captures
                        (see Set Operations > intersection).
  -o, --output <format>
                        Output results as a file with format type.
  -s, --symmetric-difference
                        Packets unique to each packet capture.
                        (see Set Operations > symmetric difference).
  -u, --union           All unique packets across all pcaket captures.
                        (see Set Operations > union).
  -v, --verbose         Provide more context to what pcapgraph is doing.
  -V, --version         Show PcapGraph's version.
  -w                    Open pcaps in Wireshark after creation.
                        (shortcut for --output pcap --output wireshark)
  -x, --exclude-empty   eXclude pcap files from being saved if they are empty.
  -2, --strip-l2        Remove layer2 bits and encode raw IP packets.
                        Use if pcaps track flows across layer 3 boundaries or
                        L2 frame formats differ between pcaps (e.g. An AP will
                        have Eth/Wi-Fi interfaces that encode 802.3/802.11).
  -3, --strip-l3        Remove IP header and encode dummy ethernet/IP headers
                        Use if pcaps track flows across IPv4 NAT.
                        -3 implies -2. IPv4 only as IPv6 should not have NAT.

About:
  Analyze packet captures with graphs and set operations. Graphs will show
  the temporal overlap of packets. Set operations can help with flow-based
  troubleshooting across multiple interfaces or devices.
  The default behavior for output is a graph (hence the name).

  Official documentation: https://pcapgraph.readthedocs.io/

Input:
  *<file>...*

  One or more files or directories. When PcapGraph detects a
  directory, it will go one level deep to find packet captures.
  This program can read all files that can be read by tshark.

  packet capture:
      `pcapng, pcap, cap, dmp, 5vw, TRC0, TRC1,
      enc, trc, fdc, syc, bfr, tr1, snoop`

Output:
  *[--output <format>]...*

  If no format is specified, a graph is printed to the screen and stdout.
  Image formats are those supported by matplotlib on your system. You can see
  which ones are available by running this in your python interpreter:

      ``matplotlib.pyplot.gcf().canvas.get_supported_filetypes()``

  All formats are listed below:

  image:
      `eps, jpeg, jpg, pdf, pgf, png,
      ps, raw, rgba, svg, svgz, tif, tiff`

  text:
      `txt`

  packet capture:
      * pcap, pcapng: Requires a set operation for there to be packets to save.
      * generate-pcaps: Creates the pcaps simul1-3 used in documentation.
      * wireshark: Opens the pcaps from a set operation in wireshark.

      `pcap, pcapng, generate-pcaps, wireshark`

Set Operations:
  All set operations require packet captures and do the following:

  1. Find all unique packets by their ASCII hexdump value.
  2. Apply the operation and generate a list of packets.
  3. Reencode the packets in a pcap using text2pcap.

  difference:
      Remove all packets that are present in one pcap from another.

  intersection:
      Find all packets that two pcaps have in common.

  union:
      Find all unique packets found in all provided pcaps.

  symmetric difference:
      Find all packets that are unique to each pcap.

  bounded (time intersection):
      Find the first and last frames in the frame intersection of all pcaps
      according to their timestamp Use these two frames as upper and lower
      limts to return all frames in each pcap that are between these two
      frames. This can help to identify traffic that sholud be in both packet
      captures, but is in only one.

  inverse bounded (time intersection):
      Finds which packets are unique to each packet capture in a given time
      frame and saves each as a packet capture.

See Also:
  pcapgraph (https://pcapgraph.readthedocs.io):
      Comprehensive documentation for this program.

  wireshark (https://www.wireshark.org/):
      Read packet captures to troubleshoot networks.

  wireshark utils (https://www.wireshark.org/docs/man-pages/):
      CLI utils that contain or enhance wireshark functionality. These were
      used in PcapGraph: editcap, mergecap, reordercap, text2pcap, tshark

  pyshark (https://kiminewt.github.io/pyshark/):
      Python wrapper for tshark.

  scapy (https://scapy.readthedocs.io/en/latest/):
      Python program to manipulate frames.

  matplotlib (https://matplotlib.org/):
      Python package to plot 2D graphs.
"""
import docopt

import pcapgraph.manipulate_frames as mf
import pcapgraph.get_filenames as gf
import pcapgraph.draw_graph as dg
import pcapgraph.pcap_math as pm
from . import get_tshark_status


def run():
    """Main function that contains the major moving parts:

    1. Verify tshark
    2. Get filenames from CLI args
    3. Get a per-pcap frame list to be graphed/exported
           frame dict form: {<file/operation>: {frame: timestamp, ...}, ...}
    4. Draw the graph/export files
    """
    get_tshark_status()
    args = docopt.docopt(__doc__)
    filenames = sorted(gf.parse_cli_args(args))
    options = {'strip-l2': args['--strip-l2'],
               'strip-l3': args['--strip-l3'],
               'pcapng': 'pcapng' in args['--output']}
    pcap_math = pm.PcapMath(filenames, options)
    all_filenames = pcap_math.parse_set_args(args)
    pcaps_frame_dict = mf.get_pcap_frame_dict(all_filenames)
    if args['-w']:
        args['--output'].extend(['wireshark', 'pcap'])
    dg.draw_graph(pcaps_frame_dict, filenames, args['--output'])


if __name__ == '__main__':
    run()

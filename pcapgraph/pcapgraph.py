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
  pcapgraph [-acV] [--set <operation>...] [--output <format>...] \
(--dir <dir>... | <file>...)
  pcapgraph (-g | --generate-pcaps) [--int <interface>]
  pcapgraph (-h | --help)
  pcapgraph (-v | --version)

Options:
  <file>...             Any number of packet captures to analyze.
  -a, --anonymize       Anonymize packet capture file names with fictional place
                        names, devices, and interfaces.
  -c, --compare         Compare all files to the first file by ip.id and
                        ip.checksum to find the percent of packets that
                        match exactly. (see Packet Comparisions).
  -d, --dir <dir>       Specify directories to add pcaps from.
                        Can be used multiple times.
  -f, --filter <filter> Prefilter packets with a wireshark filter. Can be
                        specified multiple times, once per filter.
                        Filtering for target traffic decreases processing time.
  -g, --generate-pcaps  Generate 3 example packet captures (see Generation).
  -h, --help            Show this screen.
  -i, --int <interface> Specify the interface to capture on. Requires -g. Open
                        Wireshark to find the active interface with traffic
                        passing if you are not sure which to specify.
  -o, --output <format> Output results as a file with format type.
  -s, --set <operation> Performs a set operation on frames. Valid operations are
                        bounded, difference, intersection, and union.
                        See Set Operations for more details.
  -v, --version         Show PcapGraph's version.
  -V, --verbose         Provide more context to what pcapgraph is doing.

About:
  PcapGraph is used to determine when packet captures were taken using the
  wireshark filter 'frame.time_epoch' and creates a graph with those times.
  The default behavior for output is a graph (hence the name).

  NOTE: pcap is shorthand for packet capture and is used throughout this program

Input requirements
  Packet captures are required for this program to function. They can be
  specified either individually as files, as a directory, or any combination
  of the two. When -d/--dir is used, this program will search a directory for
  valid packet capture types (essentially any format that Wireshark supports).
  The following packet capture extensions are supported by Wireshark:
    .pcapng, .pcap, .cap, .dmp, .5vw, .TRC0, .TRC1, .enc,
    .trc, .fdc, .syc, .bfr, .tr1, .snoop

Output Formats:
  Export formats are dependent on OS capabilities. Formats may include:
    Image: eps, jpeg, jpg, pdf, pgf, png, ps, raw, rgba, svg, svgz, tif, tiff
    Other: txt, pcap

  More information on format can be found in matplotlib's online documentation:
  https://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.savefig

Set Operations:
  All set operations require take packet captures and do the following:
    1. Find all unique packets by their ASCII hexdump value.
    2. Apply the operation and generate a list of packets.
    3. Reencode the packets in a pcap using text2pcap.
  pcapgraph will only run the last set operation specified (of -ditu).

  difference: Remove all packets that are present in one pcap from another.
  intersection: Find all packets that two pcaps have in common.
  union: Find all unique packets found in all provided pcaps.

  bounded (intersection):
    Find the first and last frames in the frame intersection of all pcaps
    according to their timestamp Use these two frames as upper and lower
    limts to return all frames in each pcap that are between these two
    frames. This can help to identify traffic that sholud be in both packet
    captures, but is in only one.

Packet comparisons:
  The first packet capture argument to pcapgraph will be used as a pivot to
  compare to other packet captures to compute fraction similar if -c is
  specified This is useful in determining overlap of pcaps; however,
  this is slow, so you may want to filter your pcaps before using this option.

  Comparison speed tests *per file* added as param (on a 6-year-old laptop):
    25K packets x 25K packets: 12s with -c, 6s without
    50K packets x 50K packets: 20s with -c, 10s without
    100K packets x 100K packets: 50s with -c, 25s without

Generation of example packet captures
  Creates 3 packet captures with a ping + nslookup sent every second for 100s.
  The graph from these pcaps should match the png file in examples/. When
  using this command, you may need to use sudo depending on whether you have
  configured wireshark to allow unprivileged users to take packet captures.

  Pcap1 starts at 0s, Pcap2 starts at 20s, Pcap3 starts at 40s.
  Pcap1 should match Pcap1 100%, Pcap2 66%, and Pcap3 33% (with -c used).
"""
import docopt

from . import get_tshark_status
import pcapgraph.manipulate_frames as mf
import pcapgraph.get_filenames as gf
import pcapgraph.draw_graph as dg
import pcapgraph.pcap_math as pm


def run():
    """Main function that contain the major moving parts:

    1. Verify tshark
    2. Get filenames from CLI args
    3. Get a per-pcap frame list to be graphed/exported
           frame dict form: {<file/operation>: {frame: timestamp, ...}, ...}
    4. Draw the graph/export files
    """
    get_tshark_status()
    args = docopt.docopt(__doc__)
    filenames = gf.parse_cli_args(args)
    filenames = pm.parse_set_arg(filenames, args['--set'])
    pcaps_frame_dict = mf.get_pcap_frame_dict(filenames)
    dg.draw_graph(pcaps_frame_dict, args['--output'])


if __name__ == '__main__':
    run()

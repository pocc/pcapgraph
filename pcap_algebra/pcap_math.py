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
"""Do algebraic operations on sets like union, intersect, difference."""

import subprocess as sp
import os
import json
import collections

from pcapgraph.parse_options import get_tshark_status, decode_stdout
from pcapgraph.parse_options import get_packet_count


def intersect_pcap(*pcaps):
    """Save pcap intersection. First filename is pivot packet capture.

    Assume all traffic is seen at A and parts of A's traffic are seen at
    various other points. This works best with the following kind of scenario:
        There is an application that is sending traffic from a client to a
        server across the internet

    With that scenario in mind and given these sets,
    A = (1,2,3,4,5)
    B = (1,2,3)
    C = (2,3)
    D = (3,4)

    pcap_intersection([A, B, C, D]) produces package captures and percentages:
    intersection.pcap (3)   20%
    diff_A_B (4, 5)         60%
    diff_A_C (1, 4, 5)      40%
    diff_A_D (1, 2, 5)      40%

    Percentages indicate what percentage of BCD's packets are the same as A's.
    Files starting with 'diff' are set differences of all packets to pivot A.
    """
    pcap_dict, frame_dict = parse_pcaps(*pcaps)

    # Generate intersection set of frames
    raw_frame_list = [list(pcap_dict[pcap]['raw_frames'])
                      for pcap in pcap_dict]
    frame_intersection = set(raw_frame_list[0]).intersection(*raw_frame_list)

    # Print intersection output like in docstring
    intersection_count = len(frame_intersection)
    print("{: <12} {: <}".format('SAME %', 'PCAP NAME'))
    for pcap in pcaps:
        same_percent = str(round(
            100 * (intersection_count / pcap_dict[pcap]['num_packets']))) + '%'
        print("{: <12} {: <}".format(same_percent, pcap))

    save_pcap(frame_intersection, frame_dict, name='_intersect')


def bounded_intersect_pcap(*pcaps):
    """Create a packet capture intersection out of two files using ip.ids.

    Let 2 packet captures have the following packets and assume that traffic
    originates behind the device that Pcap1 is capturing on:

    Pcap1                           Pcap2
    A                               W
    B                               X
    C                               A
    D                               B
    E                               F
    F                               M
    G                               C
    H                               G
    I                               L

    The algorithm would have found that packet A is the earliest common packet
    and that G is the latest common packet. The returned pcaps would like so:

    Pcap1                           Pcap2
    A                               A
    B                               B
    C                               F
    D                               M
    E                               C
    F                               G
    G

    NOTES
        * In Pcap2, M does not exist in Pcap1
        * In Pcap2, F is out of order compared to Pcap1

    Create a packet capture by finding the earliest common packet by and
    then the latest common packet in both pcaps by ip.id. Then return


    Args:
        *pcaps (*list(string)): Filenames of packet captures passed in.
    """
    # Init vars
    get_tshark_status()  # Set tshark environmental vars as necessary
    pcap_dict, frame_dict = parse_pcaps(*pcaps)

    min_frame, max_frame = get_minmax_common_frames(pcap_dict, frame_dict)

    # Create a bounding box around each packet capture where the bounds are
    # the min and max packets in the intersection.
    for pcap in pcap_dict:
        min_frame_index = -1
        max_frame_index = -1
        for frame in pcap_dict[pcap]['raw_frames']:
            if frame == min_frame:
                min_frame_index = pcap_dict[pcap]['raw_frames'].index(frame)
                break
        if min_frame_index == -1:
            print("ERROR: Bounding minimum packet not found!")
            raise IndexError
        for frame in reversed(pcap_dict[pcap]['raw_frames']):
            if frame == max_frame:
                max_frame_index = pcap_dict[pcap]['raw_frames'].index(frame)
                break
        if max_frame_index == -1:
            print("ERROR: Bounding maximum packet not found!")
            raise IndexError

        bounded_pcap = \
            pcap_dict[pcap]['raw_frames'][min_frame_index:max_frame_index + 1]
        # Split off file path and extension
        filename = os.path.splitext(os.path.basename(pcap))[0]
        save_pcap(bounded_pcap, frame_dict, '_bounded_intersect-' + filename)


def union_pcap(*pcaps):
    """Given sets A = (1, 2, 3), B = (2, 3, 4), A + B = (1, 2, 3, 4).

    About:
        This method uses tshark to get identifying information on
        pcaps and then mergepcap to save the combined pcap.

    Use case:
        * For a packet capture that contains a broadcast storm, this function
          will find unique packets.
        * For any other situation where you need to find all unique packets.
        * This function can be lossy with timestamps because excluding
          packets in diff pcaps with diff timestamps, but same content is the
          purpose of this function.

    Similar wireshark tool: mergecap <file>... -w union.pcap
        Merges multiple pcaps and saves them as a union.pcap (preserves
        timestamps). This method does the same thing without duplicates.\
        mergecap is shipped with wireshark.

    Args:
        *pcaps (list(str)): List of pcap filenames.
    """
    pcap_dict, frame_dict = parse_pcaps(*pcaps)
    raw_packet_list = []
    for pcap in pcap_dict:
        for frame in pcap_dict[pcap]['raw_frames']:
            raw_packet_list.append(frame)

    print("Packet statistics", collections.Counter(raw_packet_list))
    save_pcap(set(raw_packet_list), frame_dict, name='_union')


def difference_pcap(*pcaps):
    """Given sets A = (1, 2, 3), B = (2, 3, 4), C = (3, 4, 5), A-B-C = (1).

    This method will find the intersection using bounded_intersect_pcap() and
    then remove those packets from A, and save with tshark.
    """
    minuend_name = pcaps[0]
    _, minuend_frame_dict = parse_pcaps(minuend_name)
    diffing_pcaps = pcaps[1:]
    _, frame_dict = parse_pcaps(*diffing_pcaps)
    packet_diff = set(minuend_frame_dict).difference(set(frame_dict))
    save_pcap(frames=packet_diff, frame_dict=minuend_frame_dict,
              name='_difference')


def parse_pcaps(*pcaps):
    """Given *pcaps, return all frames and their timestamps.

    Args:
        *pcaps (*list(string)): A list of pcap filenames
    Returns:
        pcap_dict (dict):
            {<pcap>: {'raw_frames': [<frame>, ...], 'num_packets': 5}, ...}
        frame_dict (dict):
            {<raw_frame>: <timestamp>, ...}
    """
    pcap_dict = {}
    frame_dict = {}
    # Using packet text as dict key ensures no duplicate packets. The result
    # of this for loop is a pcap_dict with all unique packets from all pcaps.
    for pcap in pcaps:
        pcap_dict[pcap] = {'raw_frames': [], 'num_packets': 0}
        packet_dict = get_pcap_as_json(pcap)
        pcap_dict[pcap]['num_packets'] = get_packet_count(pcap)
        for packet in packet_dict:
            raw_frame = packet['_source']['layers']['frame_raw']
            frame_time_epoch = \
                packet['_source']['layers']['frame']['frame.time_epoch']
            pcap_dict[pcap]['raw_frames'].append(raw_frame)
            # frame_dict is separate from pcap_dict because one is dependent
            # on the pcap and is not for the union operation
            frame_dict[raw_frame] = frame_time_epoch

    return pcap_dict, frame_dict


def get_minmax_common_frames(pcap_dict, frame_dict):
    """Get the frames that are the beginning and end

    write me"""
    raw_frame_list = [list(pcap_dict[pcap]['raw_frames'])
                      for pcap in pcap_dict]
    frame_intersection = set(raw_frame_list[0]).intersection(*raw_frame_list)

    # Set may reorder packets, so search for first/last.
    unix_32bit_end_of_time = 4294967296
    time_min = unix_32bit_end_of_time
    time_max = 0
    max_frame = ''
    min_frame = ''
    for frame in frame_intersection:
        frame_time = float(frame_dict[frame])
        if frame_time > time_max:
            time_max = frame_time
            max_frame = frame
        if frame_time < time_min:
            time_min = frame_time
            min_frame = frame

    # If min/max frames are '', that likely means the intersection is empty.
    assert max_frame != ''
    assert min_frame != ''

    return min_frame, max_frame


def search_for_common_frame(*frame_lists):
    """Search for a common frame by iterating through list1 and then list2.

    Default is to go in forward direction.
    To search the both lists in reverse, pass in 2 reversed lists.

    Args:
        *frame_lists (list): List of ip_ids from pcap1
    Returns:
        (tuple(int)): Frame numbers of first found common frame.
    """
    for pcap in frame_lists:
        for packet in pcap:
            ip_id = packet['_source']['layers']['ip']['ip.id']

    for pcap1_index, _ in enumerate(frame_lists[0]):
        print(pcap1_index)
        pcap1_packet_ip_id = frame_list1[pcap1_index]
        for pcap2_index, _ in enumerate(frame_list2):
            print(pcap2_index)
            pcap2_packet_ip_id = frame_list2[pcap2_index]
            if pcap1_packet_ip_id == pcap2_packet_ip_id:
                return pcap1_index + 1, pcap2_index + 1


def get_pcap_as_json(pcap):
    """Given a pcap, return a json with `tshark -r <file> -x -T json`.

    tshark -r <pcap> -w -
        Pipes packet capture one packet per line to stdout
    tshark -r -
        Read file from stdin
    tshark -r <in.pcap> -x | text2pcap - <out.pcap>
        Prints hex of pcap to stdout and then resaves it as a pcap. This
        WILL delete packet timestamps as that is not encoded in hex output.

    Args:
        pcap (string): File name.
    Returns:
        (dict): Dict of the pcap json provided by tshark.
    """
    get_json_cmds = ['tshark', '-r', pcap, '-x', '-T', 'json']
    pcap_json_raw = sp.Popen(get_json_cmds, stdout=sp.PIPE).communicate()[0]
    pcap_json = ''
    if pcap_json_raw:  # Don't want json.loads to crash due to an empty string.
        pcap_json = json.loads(pcap_json_raw)
    return pcap_json


def convert_to_pcaptext(raw_packet, timestamp=''):
    """Convert the raw pcap hex to a form that text2cap can read from stdin.

    `tshark -r <file> -T json -x` produces the "in" and text2pcap
    requires the "out" formats as shown below:

    Per Text2pcap documentation:
    "Text2pcap understands a hexdump of the form generated by od -Ax -tx1 -v."

    In format (newlines added for readability):
        247703511344881544abbfdd0800452000542bbc00007901e8fd080808080a301290000
        082a563110001f930ab5b00000000a9e80d0000000000101112131415161718191a1b1c
        1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637

    Out format:
        0000  24 77 03 51 13 44 88 15 44 ab bf dd 08 00 45 20
        0010  00 54 2b bc 00 00 79 01 e8 fd 08 08 08 08 0a 30
        0020  12 90 00 00 82 a5 63 11 00 01 f9 30 ab 5b 00 00
        0030  00 00 a9 e8 0d 00 00 00 00 00 10 11 12 13 14 15
        0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
        0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
        0060  36 37

    NOTE: Output format doesn't need an extra \n between packets. So in the
    above example, the next line could be 0000  00 ... for the next packet.

    Args:
        raw_packet (string): The ASCII hexdump seen above in 'In'
        timestamp (string): Unix epoch timestamp of packet. This is optional.
            If one is passed in, it will precede the 0000 line of the packet.
    """
    # init vars
    formatted_string = ''
    hex_chars_per_line = 32
    hex_chars_per_byte = 2
    num_chars = len(raw_packet)

    if timestamp:
        formatted_string += str(timestamp) + '\n'
    # Parse the string into lines and each line into space-delimited bytes.
    for line_sep in range(0, num_chars, hex_chars_per_line):
        raw_line = raw_packet[line_sep: line_sep + hex_chars_per_line]
        line = ''
        for byte_sep in range(0, hex_chars_per_line, hex_chars_per_byte):
            line += raw_line[byte_sep: byte_sep + hex_chars_per_byte] + ' '
        line = line[:-1]  # get rid of trailing space
        line_sep_hex = line_sep // 32 * 10  # Offsets need to be in hex.
        formatted_string += '{:>04d}'.format(line_sep_hex) + '  ' + line + '\n'

    return formatted_string


def reorder_packets(pcap):
    """Union causes packets to be ordered incorrectly, so reorder properly.

    Reorder packets, save to 2nd file. After this is done, remove initial file.

    Args:
        pcap (str): Filename of packet capture. Should start with '_', which
            can be stripped off so that we can reorder to a diff file.
    """
    reorder_packets_cmds = ['reordercap', pcap, pcap[1:]]
    reorder_sp = sp.Popen(reorder_packets_cmds, stdout=sp.PIPE, stderr=sp.PIPE)
    reorder_sp.communicate()
    os.remove(pcap)


def save_pcap(frames, frame_dict, name):
    """Save a packet capture given ASCII hexdump using `text2pcap`

    Args:
        frames (set): Set of ASCII hexdump-formatted frames
        frame_dict (dict): Dict of frames to timestamps
        name (str): Type of operation and name of savefile
    """
    pcap_text = ''
    for packet in frames:  # Only send in unique values.
        frame_timestamp = frame_dict[packet]
        pcap_text += convert_to_pcaptext(packet, frame_timestamp)
    save_pcap_cmds = ['text2pcap', '-', name + '.pcap', '-t', '%s.']
    save_pcap_sp = sp.Popen(save_pcap_cmds, stdin=sp.PIPE,
                            stdout=sp.PIPE, stderr=sp.PIPE)
    save_pcap_sp.communicate(input=pcap_text.encode())
    reorder_packets(name + '.pcap')

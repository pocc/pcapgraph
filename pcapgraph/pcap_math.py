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
import collections

from pcapgraph.manipulate_frames import parse_pcaps, get_frame_dict


def parse_set_arg(args, filenames):
    """Call the appropriate method per CLI flags.

    difference, union, intersect consist of {<op>: {frame: timestamp, ...}}
    bounded_intersect consists of {pcap: {frame: timestamp, ...}, ...}
    """
    pcap_frames = {}
    for arg in args:
        if arg == 'difference':
            pcap_frames = {**pcap_frames, **difference_pcap(filenames)}
        elif arg == 'intersection':
            pcap_frames = {**pcap_frames, **intersect_pcap(filenames)}
        elif arg == 'union':
            pcap_frames = {**pcap_frames, **union_pcap(filenames)}
        elif arg == 'bounded':
            pcap_frames = {**pcap_frames, **bounded_intersect_pcap(filenames)}
        else:
            raise SyntaxError("ERROR: Invalid set operation.\nValid set "
                              "operations: Bounded, Difference, Intersection, "
                              "Union.")

    return pcap_frames


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

    Args:

    Returns:

    """
    pcap_dict, frame_dict = parse_pcaps(*pcaps)

    # Generate intersection set of frames
    raw_frame_list = [
        list(pcap_dict[pcap]['raw_frames']) for pcap in pcap_dict
    ]
    frame_intersection = set(raw_frame_list[0]).intersection(*raw_frame_list)

    # Print intersection output like in docstring
    intersection_count = len(frame_intersection)
    print("{: <12} {: <}".format('SAME %', 'PCAP NAME'))
    for pcap in pcaps:
        same_percent = str(
            round(100 * (intersection_count / pcap_dict[pcap]['num_packets']
                         ))) + '%'
        print("{: <12} {: <}".format(same_percent, pcap))

    intersect_frame_dict = {}
    for frame in frame_intersection:
        intersect_frame_dict[frame] = frame_dict[frame]
    return {'intersect': intersect_frame_dict}


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
    bounded_pcaps = []
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

        bounded_frame_list = \
            pcap_dict[pcap]['raw_frames'][min_frame_index:max_frame_index + 1]
        bounded_pcap_with_timestamps = {}
        for frame in bounded_frame_list:
            bounded_pcap_with_timestamps[frame] = frame_dict[frame]
        bounded_pcaps.append(bounded_pcap_with_timestamps)

    return bounded_pcaps


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
    pcap_dict = parse_pcaps(*pcaps)
    frame_dict = get_frame_dict(pcap_dict)
    raw_packet_list = []
    for pcap in pcap_dict:
        for frame in pcap:
            raw_packet_list.append(frame['_source']['layers']['frame_raw'][0])

    print("Packet statistics", collections.Counter(raw_packet_list))

    union_frame_dict = {}
    for frame in raw_packet_list:
        union_frame_dict[frame] = frame_dict[frame]
    return {'union': union_frame_dict}


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

    diff_frame_dict = {}
    for frame in packet_diff:
        diff_frame_dict[frame] = frame_dict[frame]
    return {'difference': diff_frame_dict}


def get_minmax_common_frames(pcap_dict, frame_dict):
    """Get the frames that are at the beginning and end of intersection pcap.

    Args:
        pcap_dict (dict):
            {<pcap>: {'raw_frames': [<frame>, ...], 'num_packets': 1}, ...}
        frame_dict (dict):
            {<raw_frame>: <timestamp>, ...}
    Returns:
        min_frame, max_frame (tuple(string)):
            Packet strings of the packets that are at the beginning and end of
            the intersection pcap based on timestamps.
    Raises:
        assert: If intersection is empty.
    """
    raw_frame_list = [
        list(pcap_dict[pcap]['raw_frames']) for pcap in pcap_dict
    ]
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

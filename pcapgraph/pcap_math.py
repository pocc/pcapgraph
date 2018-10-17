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
import os
import time

from pcapgraph.manipulate_frames import parse_pcaps
from pcapgraph.manipulate_frames import get_flat_frame_dict
from pcapgraph.manipulate_frames import get_pcap_frame_dict
from pcapgraph.manipulate_frames import get_frame_from_json
from pcapgraph.save_file import convert_to_pcaptext
import pcapgraph.save_file as save


def parse_set_arg(filenames, args):
    """Call the appropriate method per CLI flags.

    difference, union, intersect consist of {<op>: {frame: timestamp, ...}}
    bounded_intersect consists of {pcap: {frame: timestamp, ...}, ...}

    Args:
        filenames (list): List of filenames
        args (dict): Dict of all arguments (including set args).
    """
    set_args = {
        'union': args['--union'],
        'intersection': args['--intersection'],
        'difference': args['--difference'],
        'symmetric-difference': args['--symmetric-difference'],
        'bounded-intersect': args['--bounded-intersection'],
        'inverse-bounded': args['--inverse-bounded']
    }
    new_files = []
    bounded_filelist = []
    if set_args['difference']:
        generated_file = difference_pcap(
            *filenames, exclude_empty=args['--exclude-empty'])
        # As long as the difference exists and .
        if generated_file and not args['--exclude-empty']:
            new_files.append(generated_file)
    if set_args['intersection']:
        generated_file = intersect_pcap(*filenames)
        new_files.append(generated_file)
    if set_args['symmetric-difference']:
        generated_filelist = symmetric_difference_pcap(
            *filenames, exclude_empty=args['--exclude-empty'])
        new_files.extend(generated_filelist)
    if set_args['union']:
        generated_file = union_pcap(*filenames)
        new_files.append(generated_file)

    if set_args['bounded-intersect']:
        bounded_filelist = bounded_intersect_pcap(*filenames)
        new_files.extend(bounded_filelist)
    if set_args['inverse-bounded']:
        generated_filelist = inverse_bounded_intersect_pcap(
            *filenames,
            bounded_filelist=bounded_filelist,
            exclude_empty=args['--exclude-empty'])
        new_files.extend(generated_filelist)

    # Put filenames in a different place in memory so it is not altered here.
    filenames = list(filenames)
    filenames.extend(new_files)
    return filenames


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
        *pcaps: List of pcap filenames.
    Returns:
        (string): Name of generated pcap.
    """
    pcap_dict = parse_pcaps(pcaps)
    frame_dict = get_flat_frame_dict(pcap_dict)
    raw_packet_list = []
    for pcap in pcap_dict:
        for frame in pcap:
            raw_frame = get_frame_from_json(frame)
            raw_packet_list.append(raw_frame)

    print_10_most_common_frames(raw_packet_list)

    union_frame_dict = {}
    for frame in raw_packet_list:
        union_frame_dict[frame] = frame_dict[frame]
    save.save_pcap(pcap_dict=union_frame_dict, name='union.pcap')

    return 'union.pcap'


def print_10_most_common_frames(raw_packet_list):
    """After doing a packet union, find/print the 10 most common packets.

    This is a work in progress and may eventually use this bash:

    <packets> | text2pcap - - | tshark -r - -o 'gui.column.format:"No.","%m",
    "VLAN","%q","Src MAC","%uhs","Dst MAC","%uhd","Src IP","%us",
    "Dst IP","%ud","Protocol","%p","Src port","%uS","Dst port","%uD"'

    Alternatively, just use the existing information in pcap_dict.

    The goal is to print
    frame#, VLAN, src/dst MAC, src/dst IP, L4 src/dst ports, protocol

    This should likely be its own CLI flag in future.
    """
    packet_stats = collections.Counter(raw_packet_list)
    # It's not a common frame if it is only seen once.
    packet_stats = {k: v for k, v in packet_stats.items() if v > 1}
    sorted_packets = sorted(
        packet_stats, key=packet_stats.__getitem__, reverse=True)
    counter = 0
    for packet in sorted_packets:
        counter += 1
        if counter == 10:
            break
        packet_text = convert_to_pcaptext(packet)

        print("Count: {: <7}\n{: <}".format(packet_stats[packet], packet_text))
    print("To view the content of these packets, subtract the count lines, "
          "\nadd and save to <textfile>, and then run "
          "\n\ntext2pcap <textfile> out.pcap\nwireshark out.pcap\n")


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
        *pcaps: List of pcap filenames.
    Returns:
        (string): Name of generated pcap.
    """
    pcap_json_list = parse_pcaps(pcaps)
    frame_dict = get_flat_frame_dict(pcap_json_list)
    # Generate intersection set of frames
    pcap_frame_list = get_pcap_frame_dict([*pcaps])
    frame_list = [pcap_frame_list[i] for i in pcap_frame_list]
    frame_intersection = set(frame_list[0]).intersection(*frame_list[1:])

    # Print intersection output like in docstring
    intersection_count = len(frame_intersection)
    print("{: <12} {: <}".format('\nSAME %', 'PCAP NAME'))
    for pcap in pcaps:
        same_percent = str(
            round(100 * (intersection_count / len(frame_list[0])))) + '%'
        print("{: <12} {: <}".format(same_percent, pcap))

    intersect_frame_dict = {}
    for frame in frame_intersection:
        intersect_frame_dict[frame] = frame_dict[frame]
    save.save_pcap(pcap_dict=intersect_frame_dict, name='intersect.pcap')

    if frame_intersection:
        return 'intersect.pcap'
    print('WARNING! Intersection between ', *pcaps, ' contains no packets!')
    return ''


def difference_pcap(*pcaps, exclude_empty=False):
    """Given sets A = (1, 2, 3), B = (2, 3, 4), C = (3, 4, 5), A-B-C = (1).

    Args:
        *pcaps: List of pcap filenames.
        exclude_empty (bool): Whether to exclude empty files from saving.
    Returns:
        (string): Name of generated pcap.
    """
    minuend_name = pcaps[0]
    minuend_pcap_dict = parse_pcaps([minuend_name])
    minuend_frame_dict = get_flat_frame_dict(minuend_pcap_dict)
    diffing_pcaps = pcaps[1:]
    diff_pcap_dict = parse_pcaps(diffing_pcaps)
    diff_frame_dict = get_flat_frame_dict(diff_pcap_dict)
    packet_diff = set(minuend_frame_dict).difference(set(diff_frame_dict))

    diff_frame_dict = {}
    for frame in packet_diff:
        # Minuend frame dict should have all values we care about.
        diff_frame_dict[frame] = minuend_frame_dict[frame]
    diff_filename = 'diff_' + os.path.basename(minuend_name)
    # Save only if there are packets or -x flag is not used.
    if not packet_diff:
        print('WARNING! ' + str(pcaps[0]) + ' difference contains no packets!')
    if packet_diff or not exclude_empty:
        # If the file already exists, choose a different name.
        unique_diff_name = diff_filename
        while os.path.isfile(unique_diff_name):
            unique_diff_name = diff_filename[:-5] + '-' + \
                               str(int(time.time())) + '.pcap'
        save.save_pcap(pcap_dict=diff_frame_dict, name=unique_diff_name)
        return unique_diff_name

    return ''


def symmetric_difference_pcap(*pcaps, exclude_empty=False):
    """Given sets A = (1, 2, 3), B = (2, 3, 4), C = (3, 4, 5), A△B△C = (1, 5)

    For all pcaps, the symmetric difference produces a pcap that has the
    packets that are unique to only that pcap (unlike above where only one
    set is the result).

    Args:
        *pcaps: List of pcap filenames.
        exclude_empty (bool): Whether to exclude empty files from saving.
    Returns:
        (list(str)): Name of generated pcaps.
    """
    generated_filelist = []
    for file in pcaps:
        file_in_list = [file]
        other_files = set(pcaps) - set(file_in_list)
        # difference_pcap will generate files like difference-simul1.pcap
        diff_filename = difference_pcap(
            file, *other_files, exclude_empty=exclude_empty)
        if diff_filename:  # If diff file has packets.
            symdiff_filename = 'symdiff_' + os.path.basename(file)
            os.replace(diff_filename, symdiff_filename)
            generated_filelist.append(symdiff_filename)

    return generated_filelist


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
        *pcaps: List of pcap filenames.
    Returns:
        (list(string)): List of generated pcaps.
    """
    # Init vars
    pcap_dict = parse_pcaps(pcaps)
    flat_frame_dict = get_flat_frame_dict(pcap_dict)
    pcap_frame_dict = get_pcap_frame_dict(list(pcaps))

    bounded_pcaps = get_bounded_pcaps(pcaps, flat_frame_dict, pcap_frame_dict)
    names = []  # Names of all generated pcaps
    for index, _ in enumerate(bounded_pcaps):
        names.append('bounded_intersect-simul' + str(index + 1) + '.pcap')
        save.save_pcap(pcap_dict=bounded_pcaps[index], name=names[index])

    return names


def inverse_bounded_intersect_pcap(*filenames, bounded_filelist=False,
                                   exclude_empty=False):
    """Inverse of bounded intersection = (bounded intersect) - (intersect)

    Args:
        *filenames: List of filenames
        bounded_filelist (list): List of existing bounded pcaps generated by
            bounded_intersect_pcap()
        exclude_empty (bool): Delete files to be exported if they are empty.
    Returns:
        List of files generated by this method.
    """
    generated_filelist = []
    has_bounded_intersect_flag = False
    if not bounded_filelist:
        # Don't generate twice if flags -be are used
        # Note that this runs after bounded_intersect if it would be run
        bounded_filelist = bounded_intersect_pcap(*filenames)
        has_bounded_intersect_flag = True
    intersect_file = [intersect_pcap(*filenames)]
    for bi_file in bounded_filelist:
        difference_file = difference_pcap(
            bi_file, *intersect_file, exclude_empty=exclude_empty)
        if difference_file:
            generated_filelist.append(difference_file)
        if has_bounded_intersect_flag:
            # Do not keep bounded-intersect files if they are not necessary
            os.remove(bi_file)
    return generated_filelist


def get_bounded_pcaps(pcaps, flat_frame_dict, pcap_frame_dict):
    """Get the pcap frame list for bounded_intersect_pcap

    Create a bounding box around each packet capture where the bounds are
    the min and max packets in the intersection.

    Args:
        pcaps: A list of pcap filenames
        flat_frame_dict: A list of frames across all pcaps
        pcap_frame_dict: A list of frames by pcap
    Returns:
        bounded_pcaps: A list of frame_dicts
    """
    min_frame, max_frame = get_minmax_common_frames(
        list(pcaps), flat_frame_dict)

    bounded_pcaps = []
    for pcap in pcap_frame_dict:
        frame_list = list(pcap_frame_dict[pcap])
        min_frame_index = -1
        max_frame_index = -1
        for frame in frame_list:
            if frame == min_frame:
                min_frame_index = frame_list.index(frame)
                break
        if min_frame_index == -1:
            print("ERROR: Bounding minimum packet not found!")
            raise IndexError
        for frame in reversed(frame_list):
            if frame == max_frame:
                max_frame_index = frame_list.index(frame)
                break
        if max_frame_index == -1:
            print("ERROR: Bounding maximum packet not found!")
            raise IndexError

        bounded_frame_list = frame_list[min_frame_index:max_frame_index + 1]
        bounded_pcap_with_timestamps = {}
        for frame in bounded_frame_list:
            bounded_pcap_with_timestamps[frame] = flat_frame_dict[frame]
        bounded_pcaps.append(bounded_pcap_with_timestamps)

    return bounded_pcaps


def get_minmax_common_frames(pcaps, frame_dict):
    """Get the frames that are at the beginning and end of intersection pcap.

    Args:
        pcaps (list): List of pcap names.
        frame_dict (dict):
            {<raw_frame>: <timestamp>, ...}
    Returns:
        min_frame, max_frame (tuple(string)):
            Packet strings of the packets that are at the beginning and end of
            the intersection pcap based on timestamps.
    Raises:
        assert: If intersection is empty.
    """
    # Generate intersection set of frames
    pcap_frame_list = get_pcap_frame_dict(list(pcaps))
    frame_list = [list(pcap_frame_list[i]) for i in pcap_frame_list]
    frame_intersection = set(frame_list[0]).intersection(*frame_list[1:])

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

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
"""Parse the frames from files based upon options."""

import time
import subprocess as sp
import random
import json


def get_pcap_dict(filenames):
    """Return a dict with names of pcap files and their start/stop times.
    This function needs to get a dict with keys of filenames and values of
    the list of frames contained in each.

    Args:
        filenames (list): A list of filepaths.
    Returns:
        (dict): A dict with all of the data that graph functions need.
    Raises:
        IOError: Raise if there are no valid packet captures provided.
    """
    pcap_dict = parse_pcaps(list(filenames))

    if not pcap_dict:
        raise FileNotFoundError("ERROR: All packet captures are empty!")
    return pcap_dict


def parse_pcaps(pcaps):
    """Given pcaps, return all frames and their timestamps.

    Args:
        pcaps (list(string)): A list of pcap filenames
    Returns:
        pcap_dict (list): All the packet data in json format.
    """
    pcap_json_list = []
    for pcap in pcaps:
        pcap_json_list.append(get_pcap_as_json(pcap))

    return pcap_json_list


def get_flat_frame_dict(pcap_json_list):
    """Given the pcap json list, return the frame dict.

    Args:
        pcap_json_list (list): List of pcap dicts (see parse_pcaps for details)
    Returns:
        frame_list (list): [{<frame>: <timestamp>, ...}, ...]
    """
    frame_dict = {}
    for pcap in pcap_json_list:
        for frame in pcap:
            frame_raw = frame['_source']['layers']['frame_raw']
            # Some frames will have the frame string a layer deeper in a list.
            if type(frame_raw) == "<type 'list'>":
                frame_raw = frame_raw[0]

            frame_timestamp = \
                frame['_source']['layers']['frame']['frame.time_epoch']
            frame_dict[frame_raw] = frame_timestamp

    return frame_dict


def get_pcap_frame_dict(pcaps):
    """Like get_flat_frame_dict, but with pcapname as key to each frame list

    Args:
        pcaps (list): List of pcap file names.
    Returns:
        (dict): {<pcap>: {<frame>:<timestamp>, ...}, ...}
    """
    pcap_frame_list = {}
    for pcap in pcaps:
        pcap_json_list = parse_pcaps([pcap])
        pcap_frame_list[pcap] = get_flat_frame_dict(pcap_json_list)

    return pcap_frame_list


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


def anonymous_pcap_name():
    """Anonymize pcap names.

    Funny pcap names like switch_wireless is intendeded behavior.

    Returns:
        (string): Fake pcap name
    """
    fake_city_names = [
        'Hogwarts', 'Quahog', 'Lake Wobegon', 'Narnia', 'Ankh-Morpork',
        'Gotham City', 'Asgard', 'Neverland', 'The Shire', 'Rivendell',
        'Diagon Alley', 'King\'s Landing', 'Cooper Station', 'Dragonstone',
        'El Dorado', 'Atlantis', 'Pallet Town', 'Shangri-La', 'Mos Eisley'
    ]
    fake_device_names = [
        'firewall', 'router', 'access point', 'switch', 'bridge', 'repeater',
        'dial-up modem', 'proxy server', 'hub', 'tokenring mau', 'gateway',
        'turbo encabulator', 'L3 switch', 'HIDS', 'load balancer',
        'packet shaper', 'vpn concentrator', 'content filter', 'CSU/DSU'
    ]

    fake_place = random.choice(fake_city_names)
    fake_device = random.choice(fake_device_names)

    return fake_place + '-' + fake_device


def decode_stdout(stdout):
    """Given stdout, return the string."""
    return stdout.communicate()[0].decode('utf-8').strip()


def get_pcap_vars(filename):
    """Get vars given filename (see Returns).

    Args:
        filename (string): Name of the file to get data from.
    Returns:
        packet_count (int): Number of packets in a packet capture
        pcap_start (float): Unix time when this packet capture stared.
        pcap_end (float): Unix time when this packet capture ended.
    """
    packet_count = get_packet_count(filename)

    if packet_count:
        start_unixtime_cmds = [
            'tshark', '-r', filename, '-2', '-Y', 'frame.number==1', '-T',
            'fields', '-e', 'frame.time_epoch'
        ]
        end_unixtime_cmds = [
            'tshark', '-r', filename, '-2', '-Y',
            'frame.number==' + str(packet_count), '-T', 'fields', '-e',
            'frame.time_epoch'
        ]
        pcap_start_raw = sp.Popen(
            start_unixtime_cmds, stdout=sp.PIPE, stderr=sp.PIPE)
        pcap_end_raw = sp.Popen(
            end_unixtime_cmds, stdout=sp.PIPE, stderr=sp.PIPE)
        pcap_start = float(decode_stdout(pcap_start_raw))
        pcap_end = float(decode_stdout(pcap_end_raw))

        tcpdump_release_time = 946684800
        if pcap_start < tcpdump_release_time or \
                pcap_end < tcpdump_release_time:
            print("!!! Packets from ", filename, " must have traveled via "
                  "a flux capacitor because they're in the past or the future!"
                  "\n!!! Timestamps predate the release of tcpdump or "
                  "are negative.\n!!! Excluding from results.\n")
            return 0, 0, 0

        return packet_count, pcap_start, pcap_end

    # (else) May need to raise an exception for this as it means input is bad.
    print("!!! ERROR: Packet capture", filename, " has no packets or "
          "cannot be read!\n!!! Excluding from results.\n")
    return 0, 0, 0


def get_packet_count(filename):
    """Given a file, get the packet count."""
    packet_count_cmds = ['-r', filename, '-2']

    pcap_text_raw = sp.Popen(
        ['tshark', *packet_count_cmds], stdout=sp.PIPE, stderr=sp.PIPE)
    pcap_text = decode_stdout(pcap_text_raw)
    # Split text like so in order that we capture 1-line text with no newline
    packet_list = pcap_text.split('\n')
    # Filter out any packets that are the empty string
    packet_count = len(list(filter(None, packet_list)))
    return packet_count


def get_pcap_similarity(pivot_pcap, other_pcap, verbosity):
    """Compare the pivot pcap to another file.

    Take two packet captures and then compare each packet in one to each
    packet in the other by IP ID and other filters. Frames are not
    considered as there is no good way to verify that one frame is the same
    as another. FCS is discarded by the capturing device and is not
    present in packet captures.

    tshark produces two IP headers for ICMP packets. This is expected behavior.

    Args:
        pivot_pcap (string): Filename of the pivot pcap (argv[1])
        other_pcap (string): Filename of the pcap to compare to the privot pcap
        verbosity (bool): Whether to provide more info to the user.
    Return:
        (int) 1-3 digit percentage similarity between the two files
    """
    pcap_starttime = 0
    if verbosity:
        # Iterate over all packets with the given frame number.
        pcap_starttime = time.time()
        print("--compare percent similar starting for", other_pcap + "... ")

    tshark_filters = [
        '-2', '-Y', 'ip', '-T', 'fields', '-e', 'ip.id', '-e', 'ip.src', '-e',
        'ip.dst', '-e', 'tcp.ack', '-e', 'tcp.seq', '-e', 'udp.srcport'
    ]
    pivot_raw_output = \
        sp.Popen(['tshark', '-r', pivot_pcap, *tshark_filters],
                 stdout=sp.PIPE, stderr=sp.PIPE)
    pivot_pkts = set(decode_stdout(pivot_raw_output).split('\n'))
    other_raw_output = \
        sp.Popen(['tshark', '-r', other_pcap, *tshark_filters],
                 stdout=sp.PIPE, stderr=sp.PIPE)
    other_pkts = set(decode_stdout(other_raw_output).split('\n'))
    total_count = len(pivot_pkts)
    # Use python's set functions to find the fastest intersection of packets.
    same_pkts = set(pivot_pkts).intersection(other_pkts)
    similarity_count = len(same_pkts)

    percent_same = round(100 * (similarity_count / total_count))

    if verbosity:
        print("\tand it took", time.time() - pcap_starttime, 'seconds.')

    return percent_same

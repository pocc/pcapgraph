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
        frame_list (dict): {<frame>: <timestamp>, ...}
    """
    frame_dict = {}
    for pcap in pcap_json_list:
        for frame in pcap:
            frame_raw = get_frame_from_json(frame)

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


def get_frame_from_json(frame):
    """Get/sanitize raw frame from JSON of frame from `tshark -x -T json ...`

    Args:
        frame (dict): A dict of a single packet from tshark.
    Returns:
        (str): The ASCII hexdump value of a packet
    """
    frame_raw = frame['_source']['layers']['frame_raw']
    # Sometimes we get a list including the frame str instead of the frame str.
    if isinstance(frame_raw, list):
        frame_raw = frame_raw[0]
    return frame_raw


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
    pcap_json_pipe = sp.Popen(get_json_cmds, stdout=sp.PIPE)
    pcap_json_raw = pcap_json_pipe.communicate()[0]
    pcap_json_pipe.kill()
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


def get_packet_count(filename):
    """Given a file, get the packet count."""
    packet_count_cmds = ['-r', filename, '-2']

    pcap_text_pipe = sp.Popen(
        ['tshark', *packet_count_cmds], stdout=sp.PIPE, stderr=sp.PIPE)
    pcap_text = decode_stdout(pcap_text_pipe)
    pcap_text_pipe.kill()
    # Split text like so in order that we capture 1-line text with no newline
    packet_list = pcap_text.split('\n')
    # Filter out any packets that are the empty string
    packet_count = len(list(filter(None, packet_list)))
    return packet_count

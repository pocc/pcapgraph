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
"""Parse the frames from files based upon options.

Create the same JSON style with `tshark -r examples/simul1.pcap -T json -x`
Note that the <var>_raw is due to the -x flag.

::

    Frame JSON looks like this:
    {
        '_index': 'packets-2018-11-03',
        '_type': 'pcap_file',
        '_score': None,
        '_source': {
            'layers': {
                'frame_raw': ['881544abbfdd2477035113440800450000380b5d0000...
                'frame': {'frame.encap_type': '1', 'frame.time': 'Sep 26, 2...
                'eth_raw': ['881544abbfdd2477035113440800', 0, 14, 0, 1],
                'eth': {'eth.dst_raw': ['881544abbfdd', 0, 6, 0, 29], 'eth...
                'ip_raw': ['450000380b5d00004011c7980a3012900a808080', 14, 2...
                'ip': {'ip.version_raw': ['4', 14, 1, 240, 4], 'ip.version'...
                'udp_raw': ['ea6200350024a492', 34, 8, 0, 1],
                'udp': ['udp.srcport_raw': ['ea62', 34, 2, 0, 5], 'udp.srcp...
                'dns_raw': ['9b130100000100000000000006616d617a6f6e03636f6d...
                'dns': {'dns.id_raw': ['9b13', 42, 2, 0, 5], 'dns.id': '0x00...
            }
        }
    }

Many of these functions interact with this frame dict format or directly with
the frame string (seen in 'frame_raw'). The frame string is a string of the
hex of a packet.
"""

import subprocess as sp
import random
import json


def parse_pcaps(pcaps):
    """Given pcaps, return all frames and their timestamps.

    Args:
        pcaps (list): A list of pcap filenames
    Returns:
        pcap_json_list (list): All the packet data in json format.
            [{<pcap>: {PCAP JSON}}, ...]
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


def get_frame_list_by_pcap(pcap_json_dict):
    """Like get_flat_frame_dict, but with pcapname as key to each frame list

    Args:
        pcap_json_dict (dict): List of Pcap JSONs.
    Returns:
        (list): [[<frame>, ...], ...]
    """
    pcap_frame_list = []
    for pcap in pcap_json_dict.values():
        pcap_frames = []
        for frame in pcap:
            frame_str = get_frame_from_json(frame)
            pcap_frames.append(frame_str)
        pcap_frame_list.append(pcap_frames)

    return pcap_frame_list


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
    if not isinstance(frame, dict):
        print('frame is type', type(frame))
        raise TypeError("Frame must be dict!\n" + str(frame)[:120] + '...')
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
        (list): List of the pcap json provided by tshark.
    """
    if not isinstance(pcap, str):
        raise TypeError("Filename must be string!\n" + str(pcap)[:120] + '...')
    get_json_cmds = ['tshark', '-r', pcap, '-x', '-T', 'json']
    pcap_json_pipe = sp.Popen(get_json_cmds, stdout=sp.PIPE)
    pcap_json_raw = pcap_json_pipe.communicate()[0]
    pcap_json_pipe.kill()
    pcap_json_list = []
    if pcap_json_raw:  # Don't want json.loads to crash due to an empty string.
        pcap_json_list = json.loads(pcap_json_raw)
    return pcap_json_list


def strip_layers(filenames, options):
    """Get the PCAP JSON dict stripped per options.

    strip-l3:
        Replace layer 3 fields src/dst IP, ttl, checksum with dummy values
    strip-l2:
        Remove all layer 2 fields like FCS, source/dest MAC, VLAN tag...

    Args:
        filenames (list): List of filenames.
        options (dict): Whether to strip L2 and L3 headers.
    Returns:
        (dict): The modified packet dict
    """
    pcap_json_dict = {}
    for file in filenames:
        pcap_json = parse_pcaps([file])[0]
        if options['strip-l3']:
            for index, packet in enumerate(pcap_json):
                ip_raw = packet['_source']['layers']['ip_raw']
                frame_raw = packet['_source']['layers']['frame_raw']
                # Sometimes, these values will be a list instead of a string.
                if isinstance(ip_raw, list):
                    ip_raw = ip_raw[0]
                if isinstance(frame_raw, list):
                    frame_raw = frame_raw[0]
                homogenized_packet = get_homogenized_packet(ip_raw)
                pcap_json[index]['_source']['layers']['frame_raw'] = \
                    homogenized_packet + frame_raw.split(ip_raw)[1]
        elif options['strip-l2']:
            for index, packet in enumerate(pcap_json):
                eth_raw = packet['_source']['layers']['eth_raw']
                if isinstance(eth_raw, list):
                    eth_raw = eth_raw[0]  # Correct to string if list
                eth_len = len(eth_raw)
                frame_raw = packet['_source']['layers']['frame_raw']
                if isinstance(frame_raw, list):
                    frame_raw = frame_raw[0]  # Correct to string if list
                pcap_json[index]['_source']['layers']['frame_raw'] = \
                    frame_raw[eth_len:]
        pcap_json_dict[file] = pcap_json

    return pcap_json_dict


def get_homogenized_packet(ip_raw):
    """Change an IPw4 packet's fields to the same, homogenized values.

    Replace TTL, header checksum, and IP src/dst with generic values.
    This function is designed to replace all IP data that would change
    on a layer 3 boundary

    Note that these options are found only in IPv4.
    TTL is expected to change at every hop along with header
    checksum. IPs are expected to change for NAT.

    Args:
        ip_raw (str): ASCII hex of packet.
    Returns:
        (str): Packet with fields that would be altered by l3 boundary replaced
    """
    ttl = 'ff'
    ip_proto = ip_raw[18:20]
    ip_header_checksum = '1337'
    src_ip = '0a010101'
    dst_ip = '0a020202'
    homogenized_packet = ip_raw[:16] + ttl + ip_proto + \
        ip_header_checksum + src_ip + dst_ip + ip_raw[40:]
    return homogenized_packet


def anonymous_pcap_names(num_names):
    """Anonymize pcap names.

    Creation of funny pcap names like `switch_wireless` is intendeded behavior.

    Args:
        num_names (int): Number of names to be returned
    Returns:
        (list): Fake pcap name list
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
    fake_names = []

    for _ in range(num_names):
        fake_place = random.choice(fake_city_names)
        fake_device = random.choice(fake_device_names)
        fake_name = fake_place + '-' + fake_device
        fake_names.append(fake_name)

    return fake_names


def decode_stdout(stdout):
    """Given stdout, return the string."""
    return stdout.communicate()[0].decode('utf-8').strip()


def get_packet_count(filename):
    """Given a file, get the packet count.

    Args:
        filename (str): Path of a file, including extension
    Returns:
        packet_count (int): How many packets were in that pcap
    """
    packet_count_cmds = ['-r', filename, '-2']

    pcap_text_pipe = sp.Popen(['tshark', *packet_count_cmds],
                              stdout=sp.PIPE,
                              stderr=sp.PIPE)
    pcap_text = decode_stdout(pcap_text_pipe)
    pcap_text_pipe.kill()
    # Split text like so in order that we capture 1-line text with no newline
    packet_list = pcap_text.split('\n')
    # Filter out any packets that are the empty string
    packet_count = len(list(filter(None, packet_list)))
    return packet_count

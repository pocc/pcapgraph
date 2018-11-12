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

Many of these functions interact with this frame dict format or directly with
the frame string (seen in 'frame_raw'). The frame string is a string of the
hex of a packet.
"""

import subprocess as sp
import random
import re
import os


def strip_layers(pcap_framelist, options):
    """Get the PCAP JSON dict stripped per options.

    strip-l3:
        Replace layer 3 fields src/dst IP, ttl, checksum with dummy values
    strip-l2:
        Remove all layer 2 fields like FCS, source/dest MAC, VLAN tag...

    Args:
        pcap_framelist (dict): Dict of frames and timestamps with pcap as key.
        options (dict): Whether to strip L2 and L3 headers.
    Returns:
        (dict): The modified packet dict
    """
    for pcap in pcap_framelist:
        if options['strip-l3']:
            for index, frame in enumerate(pcap_framelist[pcap]['frames']):
                frame_header_end = 16
                has_vlan_tag = (frame[12:16] == '8100')
                if has_vlan_tag:
                    frame_header_end = 24
                ip_version = int(frame[frame_header_end])
                if ip_version == 4:
                    ip_header_nibbles = 8 * int(frame[frame_header_end + 1])
                else:  # IPv6 header is ALWAYS 40 octets.
                    ip_header_nibbles = 80
                ip_header_end = frame_header_end + ip_header_nibbles
                ip_header = frame[frame_header_end:ip_header_end]
                homogenized_packet = get_homogenized_packet(ip_header)
                pcap_framelist[pcap]['frames'][index] = \
                    homogenized_packet + frame.split(ip_header)[1]
        elif options['strip-l2']:
            for index, frame in enumerate(pcap_framelist[pcap]['frames']):
                eth_len = len(frame)
                pcap_framelist[pcap]['frames'][index] = frame[eth_len:]

    return pcap_framelist


def get_homogenized_packet(ip_raw):
    """Change an IPv4 packet's fields to the same, homogenized values.

    Replace TTL, header checksum, and IP src/dst with generic values.
    This function is designed to replace all IP data that would change
    on a layer 3 boundary

    TTL is expected to change at every hop along with header
    checksum. IPs are expected to change for NAT. In IPv6, only the next
    hop field is changed as IPv6 does not have NAT or checksums.

    Args:
        ip_raw (str): ASCII hex of packet.
    Returns:
        (str): Packet with fields that would be altered by l3 boundary replaced
    """
    if ip_raw[0] == '4':
        ttl = 'ff'
        ip_proto = ip_raw[18:20]
        ip_header_checksum = '1337'
        src_ip = '0a010101'
        dst_ip = '0a020202'
        homogenized_packet = ip_raw[:16] + ttl + ip_proto + \
            ip_header_checksum + src_ip + dst_ip + ip_raw[40:]
    else:
        homogenized_packet = ip_raw[:14] + '2a' + ip_raw[16:]

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


def get_pcap_info(filenames):
    """Given a list of file, get the packet count and start/stop times per file

    Args:
        filenames (list): Paths of all files, including extension
    Returns:
        pcap_info (dict): Pcap info dict following this format:
            {<PCAP NAME>: {
                'packet_count': <int>,
                'pcap_start': <float>,
                'pcap_end': <float>
            }}
    """
    pcap_formats = [
        'pcapng', 'pcap', 'cap', 'dmp', '5vw', 'TRC0', 'TRC1', 'enc', 'trc',
        'fdc', 'syc', 'bfr', 'tr1', 'snoop'
    ]
    # Remove files that are not packet captures from list.
    for filename in filenames:
        if os.path.splitext(filename)[1][1:] not in pcap_formats:
            filenames.remove(filename)

    pcap_info = {}
    packet_count_cmds = ['capinfos', '-aceS'] + filenames

    packet_count_pipe = sp.Popen(packet_count_cmds, stdout=sp.PIPE)
    packet_count_text = decode_stdout(packet_count_pipe)
    packet_count_pipe.kill()

    # Output of capinfos is tabular with below as keys.
    count_list = re.findall(r'Number of packets:\s*(\d+)', packet_count_text)
    start_times = re.findall(r'First packet time:\s*(\d+\.\d+|n\/a)',
                             packet_count_text)
    end_times = re.findall(r'Last packet time:\s*(\d+\.\d+|n\/a)',
                           packet_count_text)
    for index, filename in enumerate(filenames):
        name = os.path.basename(os.path.splitext(filename)[0])
        is_invalid_pcap = (count_list[index] == '0'
                           or start_times[index] == 'n/a'
                           or end_times[index] == 'n/a')
        if is_invalid_pcap:
            print("!!! ERROR: Packet capture ", filename,
                  " has no packets or cannot be read!\n")
            name += ' (no packets)'
        else:
            pcap_info[name] = {
                'packet_count': int(count_list[index]),
                'pcap_start': float(start_times[index]),
                'pcap_end': float(end_times[index])
            }
    if not count_list:
        raise FileNotFoundError('\nERROR: No valid packet captures found!'
                                '\nValid types: ' + ', '.join(pcap_formats))

    return pcap_info


def get_frametext_from_files(filenames):
    """ Get the hex frametext from all packet captures.

    Tshark input looks like this:
          0000  24 77 03 51 13 44 88 15 44 ab bf dd 08 00 45 20
          0010  00 54 2b bc 00 00 79 01 e8 fd 08 08 08 08 0a 30
          ...

    Frametext looks like this:
              247703511344881544abbfdd0800452000542bbc00007901e8fd08...

    Args:
        filenames (list): List of all files
    Returns:
        (dict): {<pcap>:
                    {
                        'frames': [<frame>, ...],
                        'timestamps': [<timestamp>, ...]
                    },
                ...
                }
    """
    pcap_frames = {}

    get_hex_cmds = 'tshark -x -r'.split()
    timestamp_cmds = 'tshark -T fields -e frame.time_epoch -r'.split()
    for filename in filenames:
        pcap_frames[filename] = {'frames': [], 'timestamps': []}
        sp_hex_output = sp.Popen(get_hex_cmds + [filename], stdout=sp.PIPE)
        hex_output = sp_hex_output.communicate()[0].decode('utf-8')
        # Split -x output into frame strings and filter out empty values
        frame_list = filter(None, hex_output.split('\n\n'))

        sp_timestamps = sp.Popen(timestamp_cmds + [filename], stdout=sp.PIPE)
        timestamps = sp_timestamps.communicate()[0].decode('utf-8').split('\n')

        for index, frame in enumerate(frame_list):
            framehex = ''
            frame_lines = frame.split('\n')
            for frame_line in frame_lines:
                framehex += frame_line[6:53].replace(' ', '')
            pcap_frames[filename]['frames'].append(framehex)
            pcap_frames[filename]['timestamps'].append(timestamps[index])

    return pcap_frames

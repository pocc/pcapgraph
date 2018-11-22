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
"""Parse frames as bytes objects for speed."""
import struct
import subprocess as sp
import os
import sys
import tempfile
import collections

from . import get_wireshark_version


def print_10_most_common_frames(raw_frame_list):
    """After doing a packet union, find/print the 10 most common packets.

    This is a work in progress and may eventually use this bash:

    <packets> | text2pcap - - | tshark -r - -o 'gui.column.format:"No.",
    "%m","VLAN","%q","Src MAC","%uhs","Dst MAC","%uhd","Src IP","%us",
    "Dst IP","%ud","Protocol","%p","Src port","%uS","Dst port","%uD"'

    Alternatively, just use the existing information in pcap_dict.

    The goal is to print
    frame#, VLAN, src/dst MAC, src/dst IP, L4 src/dst ports, protocol

    This should likely be its own CLI flag in future.

    Args:
        raw_frame_list (list): List of raw frames
    """
    packet_stats = collections.Counter(raw_frame_list)
    # It's not a common frame if it is only seen once.
    packet_stats = {k: v for k, v in packet_stats.items() if v > 1}
    sorted_packets = sorted(
        packet_stats, key=packet_stats.__getitem__, reverse=True)
    counter = 0
    for packet in sorted_packets:
        frame_hex = packet.hex()
        with tempfile.NamedTemporaryFile() as temp_file:
            zero_timestamp = b'\x00\x00\x00\x00\x00\x00\x00\x00'
            write_file_bytes(temp_file.name, [packet], [zero_timestamp])
            tshark_cmds = ('tshark -r' + temp_file.name).split(' ')
            sp_pipe = sp.Popen(tshark_cmds, stdout=sp.PIPE, stderr=sp.PIPE)
            formatted_packet = sp_pipe.communicate()[0].decode('utf-8')
            counter += 1
            if counter == 10:
                break
            print("Count: {: <7}\n{: <}\n{: <}".format(
                packet_stats[packet],
                'Frame hex: ' + frame_hex,
                formatted_packet
            ))
    print("To view the content of these packets, subtract the count lines,"
          "\nadd and save to <textfile>, and then run "
          "\n\ntext2pcap <textfile> out.pcap\nwireshark out.pcap\n")


def get_frame_ts_bytes(file_bytes, endianness):
    """Parse .pcap files
    Format: https://wiki.wireshark.org/Development/LibpcapFileFormat
    Example: http://www.kroosec.com/2012/10/a-look-at-pcap-file-format.html
    """
    # B = byte, H = 2B, I = 4B, Q = 8B. Lowercase versions are signed.
    # (I) Magic Number | (H) Major Version | (H) Minor Version |
    # (i) Timezone Offset | (I) Timestamp Accuracy |
    # (I) Snapshot Length | (I) Link-Layer Header Type

    pcap_header = struct.unpack(endianness + 'IHHiIII', file_bytes[:24])
    b_index = 24
    pcap_end = len(file_bytes)
    frames = []
    timestamps = []
    while b_index < pcap_end:
        if pcap_header[3]:  # If there is a timezone offset, add to timestamp
            timestamp_sec = struct.unpack(endianness + 'I',
                                          file_bytes[b_index:b_index + 4])
            timestamp_sec += int(pcap_header[3])
            timestamp_bytes = struct.pack(endianness + 'I', timestamp_sec)\
                + file_bytes[b_index + 4: b_index + 8]
        else:
            timestamp_bytes = file_bytes[b_index: b_index + 8]
        timestamps.append(timestamp_bytes)
        frame_len = struct.unpack(endianness + 'I',
                                  file_bytes[b_index + 12:b_index + 16])[0]
        b_index += 16  # Move index 16 bytes for timestamp
        frames.append(file_bytes[b_index:b_index + frame_len])
        b_index += frame_len

    return frames, timestamps


def get_pcap_bytes_from_non_pcap(filename):
    """For a file that doesn't end in .pcap, convert to .pcap

    Use a temproray file as a destination for whatever fileytpe this
    and then read from it into a bytes object.

    Args:
        filename (str): Path to file that is not a pcap
    Returns:
        (bytes): Bytes object of converted pcap file
    """
    with tempfile.NamedTemporaryFile() as temp_file:
        editcap_cmd_str = 'editcap -F pcap ' + filename + ' ' + temp_file.name
        editcap_cmds = editcap_cmd_str.split(' ')
        sp_pipe = sp.Popen(editcap_cmds)
        sp_pipe.communicate()
        with open(temp_file.name, 'rb') as file_obj:
            pcap_bytes = file_obj.read()

    return pcap_bytes


def get_bytes_from_pcaps(filenames):
    """Parse pcap into bytes object and convert to pcap as necessary.

    Args:
        filenames (list): Files to be parsed into bytes.
    Returns:
        (dict): List of frame bytes and list of timestamp bytes by pcap
    """
    # If not pcap, convert to pcap. All editcap types will now be supported.
    pcap_dict = {}
    for filename in filenames:
        if os.path.splitext(filename)[1] != '.pcap':
            # If not pcap, convert to pcap and get bytes
            pcap_bytes = get_pcap_bytes_from_non_pcap(filename)
        else:
            with open(filename, 'rb') as file_obj:
                pcap_bytes = file_obj.read()
        # .pcap files must start with a magic number.
        magic_number = pcap_bytes[0:4]
        is_little_endian = (magic_number == b'\xd4\xc3\xb2\xa1')
        is_big_endian = (magic_number == b'\xa1\xb2\xc3\xd4')
        if is_little_endian:
            endianness_char = '<'
        elif is_big_endian:
            endianness_char = '>'
        else:
            raise FileNotFoundError('ERROR: Invalid packet capture encoding. ',
                                    magic_number, 'Now exiting...')

        pcap_dict[filename] = {}
        frames, timestamps = get_frame_ts_bytes(pcap_bytes, endianness_char)
        pcap_dict[filename]['frames'] = frames
        pcap_dict[filename]['timestamps'] = timestamps

    return pcap_dict


def write_file_bytes(filename, frame_list, timestamp_list):
    """Write the raw hex back to a file.

    frame_list and timestamp_list already contain bytes objects,
    so do not require any encoding.

    Args:
        filename (str): File to write to
        frame_list (list(bytes)): Frames to add to file
        timestamp_list (list(bytes)): Timestamps  to add to file
    """
    # Every frame should have a timestamp.
    assert len(frame_list) == len(timestamp_list)
    little_endian = (sys.byteorder == 'little')
    if little_endian:
        endianness_char = '<'
    else:
        endianness_char = '>'
    version = get_wireshark_version().split('.')
    # Do not use this version - for some reason wireshark does not properly
    # encode it's own version and will always put 2.4.

    pcap_header_dict = {
        'magic_number': 0xa1b2c3d4,
        'major_ver': int(version[0]),
        'minor_ver': int(version[1]),
        'utc_offset': 0,  # This is never used; don't start now.
        'timestamp_accuracy': 0,
        'snapshot_length': 0xffff,
        'link_layer_type': 1  # Encode ethernet regardless of input
    }
    pcap_header = struct.pack(endianness_char + 'IHHIiII',
                              *list(pcap_header_dict.values()))

    frame_bytes = b''
    # Reorder frames that are out-of-order. Key assumption is that
    # frames and timestamps are in the same order and correspond.
    # timestamps are in little-endian bytes, so needs conversion before sorting
    timestamp_floats = [float(0)] * len(timestamp_list)
    for index, timestamp in enumerate(timestamp_list):
        seconds, fraction = struct.unpack(endianness_char + 'II', timestamp)
        microseconds = str(fraction).zfill(6)
        timestamp_floats[index] = float(str(seconds) + '.' + microseconds)
    sort_order = sorted(range(len(timestamp_floats)),
                        key=timestamp_floats.__getitem__)
    # Index is the ordinal of the timestamp that is next numerically
    for i in sort_order:
        frame_len = len(frame_list[i])
        frame_lengths = struct.pack('<II', frame_len, frame_len)
        frame_bytes += timestamp_list[i] + frame_lengths + frame_list[i]

    with open(filename, 'wb') as file:
        file.write(pcap_header + frame_bytes)

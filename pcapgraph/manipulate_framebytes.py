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

from . import get_wireshark_version


def parse_pcap(file_bytes, endianness_char):
    """Parse .pcap files
    Format: https://wiki.wireshark.org/Development/LibpcapFileFormat
    Example: http://www.kroosec.com/2012/10/a-look-at-pcap-file-format.html
    """
    # B = byte, H = 2B, I = 4B, Q = 8B. Lowercase versions are signed.
    # (I) Magic Number | (H) Major Version | (H) Minor Version |
    # (i) Timezone Offset | (I) Timestamp Accuracy |
    # (I) Snapshot Length | (I) Link-Layer Header Type

    # Unpack the header like so: struct.unpack('<IHHiIII', file_bytes[:24])
    b_index = 24
    pcap_end = len(file_bytes)
    frames = []
    timestamps = []
    while b_index < pcap_end:
        timestamps.append(file_bytes[b_index:b_index + 8])
        frame_len = struct.unpack(endianness_char + 'I',
                                  file_bytes[b_index + 12:b_index + 16])[0]
        b_index += 16  # Move index 16 bytes for timestamp
        frames.append(file_bytes[b_index:b_index + frame_len])
        b_index += frame_len

    return frames, timestamps


def convert_to_pcap(filename):
    """Convert other formats to pcap."""
    filename_base = os.path.splitext(os.path.basename(filename))[0]
    new_file = filename_base + '.pcap'
    editcap_cmds = ('editcap -F pcap ' + filename + ' ' + new_file).split(' ')
    sp.Popen(editcap_cmds)
    return new_file


def parse_pcaps(filename):
    """Parse pcap into bytes object and convert to pcap as necessary.

    Args:
        filename (str): File to be parsed into bytes.
    Returns:
        (tuple): List of frame bytes and list of timestamp bytes.
    """
    # If not pcap, convert to pcap. All editcap types will now be supported.
    old_filename = ''
    if os.path.splitext(filename)[1] != '.pcap':
        old_filename = str(filename)
        filename = convert_to_pcap(filename)
        while not os.path.isfile(filename):  # Wait for file to be written
            pass
    with open(filename, 'rb') as file_obj:
        pcap_bytes = file_obj.read()
    if old_filename:  # If we created a temporary pcap file, detele it
        os.remove(filename)
    # .pcap files must start with a magic number.
    magic_number = pcap_bytes[0:4]
    is_little_endian = (magic_number == b'\xd4\xc3\xb2\xa1')
    is_big_endian = (magic_number == b'\xa1\xb2\xc3\xd4')
    if is_little_endian:
        endianness_char = '<'
    elif is_big_endian:
        endianness_char = '>'
    else:
        raise FileNotFoundError('ERROR: Invalid packet capture encoding. '
                                'Now exiting...')

    return parse_pcap(pcap_bytes, endianness_char)


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
    for index, frame in enumerate(frame_list):
        frame_lengths = struct.pack('<II', len(frame), len(frame))
        frame_bytes += timestamp_list[index] + frame_lengths + frame

    with open(filename, 'wb') as file:
        file.write(pcap_header + frame_bytes)

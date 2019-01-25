# -*- coding: utf-8 -*-
# Copyright 2018-2019 Ross Jacobs All Rights Reserved.
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
"""Class to interface with Wireshark and access pcaket captures.

ALL wireshark utilities
"""
import os
import re
import sys
import time
import subprocess as sp
import webbrowser
import shutil

# Track wireshark utils used at top of file
CAPINFOS_CMD = 'capinfos'
WIRESHARK_CMD = 'wireshark'
TSHARK_CMD = 'tshark'
EDITCAP_CMD = 'editcap'


def verify_wireshark():
    """Errors and quits if tshark is not installed.

    On Windows, tshark may not be recognized by cmd even if Wireshark is
    installed. On Windows, this function will add the Wireshark folder to
    path so `tshark` can be called.

    Changing os.environ will only affect the cmd shell this program is
    using (tested). Not using setx here as that is potentially destructive.

    Raises FileNotFonudError:
        If wireshark is not found, raise an error as they are required.
    """
    if sys.platform == 'win32':
        os.environ["PATH"] += os.pathsep + os.pathsep.join(
            ["C:\\Program Files\\Wireshark"])
    is_tshark_on_path = shutil.which(CAPINFOS_CMD)
    if not is_tshark_on_path:
        print("\nERROR:  Requirement tshark from Wireshark not found!",
              "\n\t\tPlease install Wireshark or add tshark to your PATH.",
              "\n\nOpening Wireshark download page...")
        time.sleep(2)
        webbrowser.open('https://www.wireshark.org/download.html')
        raise FileNotFoundError


def get_wireshark_version():
    """Get the wireshark version in the form of '1.2.3'"""
    command_list = (WIRESHARK_CMD + ' -v').split()
    sp_pipe = sp.Popen(command_list, stdout=sp.PIPE, stderr=sp.PIPE)
    wireshark_v = sp_pipe.communicate()[0].decode('utf-8')
    return wireshark_v.split(' ')[1]  # Version is 2nd word


def parse_filenames(files):
    """Get all pcaps from user-entered args

    Args:
        files (list): User-entered files and directories to find pcaps
    Returns:
        List of fully-specified files
    """
    # Flatten any entered directories
    all_files = []
    for file in files:
        if os.path.isdir(file):
            filepaths = abs_filepaths(os.listdir(file))
        else:
            filepaths = abs_filepaths([file])
        all_files.extend(filepaths)

    # All tshark-supported pcap types
    pcap_ext_regex = re.compile(
        r'\.pcapng$|\.pcap$|\.cap$|\.dmp$|\.5vw$|\.TRC0$|\.TRC1|'
        r'\.enc$|\.trc$|\.fdc$|\.syc$|\.bfr$|\.tr1$|\.snoop$')
    return list(filter(pcap_ext_regex.search, all_files))


def abs_filepaths(files):
    """Get absolute filepaths.

    Args:
        files (list): List of files to get absolute paths for
    Returns:
        List of absolute filepaths
    """
    file_list = []
    for file in files:
        file = os.path.expanduser(file)
        file = os.path.abspath(file)
        file_list.append(file)

    return file_list


def decode_stdout(stdout):
    """Given stdout, return the string."""
    return stdout.communicate()[0].decode('utf-8').strip()


def get_tshark_output(file):
    """Get formatted packets from tshark."""
    tshark_cmds = [TSHARK_CMD, '-r', file]
    sp_pipe = sp.Popen(tshark_cmds, stdout=sp.PIPE, stderr=sp.PIPE)
    formatted_packets = decode_stdout(sp_pipe)
    return formatted_packets


def convert_to_pcap(file, to_file):
    """Convert from any filetype to a pcap using editcap."""
    editcap_cmd_str = EDITCAP_CMD + ' -F pcap ' + file + ' ' + to_file
    editcap_cmds = editcap_cmd_str.split(' ')
    sp_pipe = sp.Popen(editcap_cmds)
    sp_pipe.communicate()


def get_pcap_info(filenames):
    """Given a list of file, get the packet count and start/stop times per file

    Found/documented a capinfos bug where it quits on an open/read error.
    Wireshark bug 15433:
        https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=15433
    >> Execute capinfos once per file until fix is in most installations.

    NOTE: A file in `filenames` MUST have a valid path.


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
    pcap_info = {}
    packet_count = 0
    pcap_formats = [
        'pcapng', 'pcap', 'cap', 'dmp', '5vw', 'TRC0', 'TRC1', 'enc', 'trc',
        'fdc', 'syc', 'bfr', 'tr1', 'snoop'
    ]

    for filename in filenames:
        # Files that are not packet captures should not be in this list.
        assert os.path.splitext(filename)[1][1:] in pcap_formats

        packet_count_cmds = [CAPINFOS_CMD, '-MaceS', filename]
        packet_count_pipe = sp.Popen(packet_count_cmds, stdout=sp.PIPE)
        packet_count_text = decode_stdout(packet_count_pipe)
        packet_count_pipe.kill()

        # Output of capinfos is tabular with below as keys.
        packet_count = re.findall(r'Number of packets:\s*(\d+)',
                                  packet_count_text)[0]
        start_time = re.findall(r'First packet time:\s*(\d+\.\d+|n/a)',
                                packet_count_text)[0]
        end_time = re.findall(r'Last packet time:\s*(\d+\.\d+|n/a)',
                              packet_count_text)[0]

        name = os.path.basename(os.path.splitext(filename)[0])
        is_invalid_packet = (packet_count == '0' or start_time == 'n/a'
                             or end_time == 'n/a')
        if is_invalid_packet:
            print("!!! ERROR: Packet capture ", filename,
                  " has no packets or cannot be read!\n")
            name += ' (no packets)'
        else:
            pcap_info[name] = {
                'packet_count': int(packet_count),
                'pcap_start': float(start_time),
                'pcap_end': float(end_time)
            }
    if not packet_count:
        raise FileNotFoundError('\nERROR: No valid packet captures found!'
                                '\nValid types: ' + ', '.join(pcap_formats))

    return pcap_info


def get_tshark_version():
    """Get tshark version information."""
    tshark_cmds = [TSHARK_CMD, '--version']
    sp_pipe = sp.Popen(tshark_cmds, stdout=sp.PIPE, stderr=sp.PIPE)
    tshark_version_paragraph = decode_stdout(sp_pipe)
    tshark_version_line = tshark_version_paragraph.split('\n')[0]
    return tshark_version_line


def open_in_wireshark(files):
    """Open file(s) in wireshark.

    Args:
        files: String or list of strings of filenames
    Returns:
        pids of opened windows
    """
    pids = []
    for file in list(files):
        ws_process = sp.Popen([WIRESHARK_CMD, file])
        pids.append(ws_process.pid)

    return pids

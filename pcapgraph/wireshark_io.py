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
"""Class to interface with Wireshark and access pcaket captures."""
import os
import re
import sys
import time
import subprocess as sp
import webbrowser
import shutil


def check_requirements():
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
    is_tshark_on_path = shutil.which('tshark')
    if not is_tshark_on_path:
        print("\nERROR:  Requirement tshark from Wireshark not found!",
              "\n\t\tPlease install Wireshark or add tshark to your PATH.",
              "\n\nOpening Wireshark download page...")
        time.sleep(2)
        webbrowser.open('https://www.wireshark.org/download.html')
        raise FileNotFoundError


def get_wireshark_version():
    """Get the wireshark version in the form of '1.2.3'"""
    command_list = 'wireshark -v'.split()
    sp_pipe = sp.Popen(command_list, stdout=sp.PIPE, stderr=sp.PIPE)
    wireshark_v = sp_pipe.communicate()[0].decode('utf-8')
    return wireshark_v.split(' ')[1]  # Version is 2nd word


def get_filenames(files):
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


def open_in_wireshark(files):
    """Open file(s) in wireshark.

    Args:
        files: String or list of strings of filenames
    """
    for file in list(files):
        sp.Popen(['wireshark', file])

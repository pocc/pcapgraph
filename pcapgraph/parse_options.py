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
"""Parse CLI options"""

import sys
import os
import time
import webbrowser
import subprocess as sp


def parse_cli_args(args):
    """Parse args with docopt. Return a list of filenames

    Args:
        args (dict): Dict of args that have been passed in via docopt.
    Return:
        (list): List of filepaths
    """
    if args['--version']:
        print('PcapGraph v1.0.0\nLicense: Apache 2')
        sys.exit()

    filenames = get_filenames_from_directories(args['--dir'])
    filenames.extend(get_filenames(args['<file>']))
    estimated_time = get_est_computation_time(filenames, args['--compare'])
    if estimated_time > 10:
        print("\nEstimated time to complete is greater than 10 seconds "
              "(i.e. grab a cup of coffee).\n")

    return filenames


def get_filenames_from_directories(directories):
    """Get all the files from all provided directories."""
    pcap_extensions = [
        '.pcapng', '.pcap', '.cap', '.dmp', '.5vw', '.TRC0', '.TRC1', '.enc',
        '.trc', '.fdc', '.syc', '.bfr', '.tr1', '.snoop'
    ]
    system = sys.platform
    cwd = os.getcwd() + '/'
    filenames = []
    for directory in directories:
        # Tilde expansion on unix systems.
        if directory[0] in '~':
            directory = os.path.expanduser(directory)
        dir_string = directory
        # If the provided path is relative.
        if system == 'win32' and "C:\\" not in directory \
                or directory[0] not in '/':
            dir_string = cwd + directory
        if not os.path.isdir(dir_string):
            print("ERROR: Directory", dir_string, "not found!")
            sys.exit()
        for file in os.listdir(dir_string):
            for pcap_ext in pcap_extensions:
                if file.endswith(pcap_ext):
                    filenames.append(directory + '/' + file)

    return filenames


def get_filenames(files):
    """Return a list of filenames."""
    pcap_extensions = [
        '.pcapng', '.pcap', '.cap', '.dmp', '.5vw', '.TRC0', '.TRC1', '.enc',
        '.trc', '.fdc', '.syc', '.bfr', '.tr1', '.snoop'
    ]
    cwd = os.getcwd() + '/'
    filenames = []
    for filename in files:
        file_string = filename
        if "C:\\" not in filename:
            file_string = cwd + filename
        if not os.path.isfile(file_string):
            print("ERROR: File", file_string, "not found!")
            sys.exit()
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in pcap_extensions:
            print("ERROR:", filename, "is not a valid packet capture!")
            print("Valid packet capture extensions:", pcap_extensions)
            sys.exit()
        filenames.append(filename)

    return filenames


def get_est_computation_time(filenames, has_campare):
    """Guess whether this process will take more than 10 seconds.

    A 100MB file is ~ 100K packets. Lazy math indicates that
    a billion packet-by-packet comparisons takes ~10s. If we reach an
    expected 1 billion packet comparisons, let the user know.

    Args:
        filenames (list): List of the names of files.
        has_campare (bool): Compare option is used (usually doubles time).
    Returns:
        (int): Seconds that this should take (largely a wild guess).
    """
    # Save size in MB
    filesizes = [os.stat(file).st_size / 10**6 for file in filenames]
    est_time = 0
    for filesize in filesizes:
        est_time += filesizes[0] * filesize
    if has_campare:  # Compare will double processing time.
        est_time *= 2

    return est_time / 100  # should return est time in seconds


def get_tshark_status():
    """Errors and quits if tshark is not installed."""
    try:
        # tshark is not necessarily on path in Windows, even if installed.
        tshark = get_tshark_cmds()
        sp.Popen([*tshark, '-v'], stdout=sp.PIPE)
    except FileNotFoundError as err:
        print(err,
              "\nERROR: Requirement tshark from Wireshark is not satisfied!",
              "\n       Please download Wireshark and try again.",
              "\n\nOpening Wireshark download page...")
        time.sleep(2)
        webbrowser.open('https://www.wireshark.org/download.html')
        sys.exit()


def get_pcap_dict(filenames, has_compare_pcaps, verbosity):
    """Return a dict with names of pcap files and their start/stop times.

    Args:
        filenames (list): A list of filepaths.
        has_compare_pcaps (bool): Has the user has provided the '-c' option.
        verbosity (bool): Whether to provide user with additional context.
    Return:
        (dict): A dict with all of the data that graph functions need.
    """
    pcap_data = {}
    # The pivot is compared against to see how much traffic is the same.
    pivot_pcap = filenames[0]

    for filename in filenames:
        packet_count, pcap_start, pcap_end = get_pcap_vars(filename)

        filename_sans_path = os.path.splitext(os.path.basename(filename))[0]
        if has_compare_pcaps:
            pivot_file_similarity = \
                get_pcap_similarity(pivot_pcap, filename, verbosity)
            if pivot_file_similarity == 0:
                pivot_file_similarity = '0'  # So that a number% is shown.
        else:
            pivot_file_similarity = None
        pcap_data[filename_sans_path] = {
            'packet_count': packet_count,
            'pcap_starttime': float(pcap_start),
            'pcap_endtime': float(pcap_end),
            'pivot_similarity': pivot_file_similarity
        }

    if verbosity:
        print("Data loaded. Now drawing graph...")
    return pcap_data


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
    tshark_cmds = get_tshark_cmds()
    packet_count_cmds = ['-r', filename, '-2']
    pcap_text_raw = sp.Popen(
        [*tshark_cmds, *packet_count_cmds], stdout=sp.PIPE)
    pcap_text = decode_stdout(pcap_text_raw)
    packet_count = pcap_text.count('\n')  # Each line of output is a packet

    start_unixtime_cmds = [
        *tshark_cmds, '-r', filename, '-2', '-Y', 'frame.number==1', '-T',
        'fields', '-e', 'frame.time_epoch'
    ]
    end_unixtime_cmds = [
        *tshark_cmds, '-r', filename, '-2', '-Y',
        'frame.number==' + str(packet_count), '-T', 'fields', '-e',
        'frame.time_epoch'
    ]
    pcap_start_raw = sp.Popen(start_unixtime_cmds, stdout=sp.PIPE)
    pcap_end_raw = sp.Popen(end_unixtime_cmds, stdout=sp.PIPE)
    pcap_start = float(decode_stdout(pcap_start_raw))
    pcap_end = float(decode_stdout(pcap_end_raw))

    return packet_count, pcap_start, pcap_end


def get_tshark_cmds():
    """Get OS-specific tshark commands. Assuming 64-bit Windows."""
    if sys.platform == 'win32':
        return ['cmd', '/c', 'C:\\"Program Files"\\Wireshark\\tshark']
    return ['tshark']


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
    tshark = get_tshark_cmds()
    tshark_filters = [
        '-2', '-Y', 'ip', '-T', 'fields', '-e', 'ip.id', '-e', 'ip.src', '-e',
        'ip.dst', '-e', 'tcp.ack', '-e', 'tcp.seq', '-e', 'udp.srcport'
    ]
    pivot_raw_output = \
        sp.Popen([*tshark, '-r', pivot_pcap, *tshark_filters], stdout=sp.PIPE)
    pivot_pkts = set(decode_stdout(pivot_raw_output).split('\n'))
    other_raw_output = \
        sp.Popen([*tshark, '-r', other_pcap, *tshark_filters], stdout=sp.PIPE)
    other_pkts = set(decode_stdout(other_raw_output).split('\n'))
    total_count = len(pivot_pkts)
    # Use python's set functions to find the fastest intersection of packets.
    same_pkts = set(pivot_pkts).intersection(other_pkts)
    similarity_count = len(same_pkts)
    percent_same = round(100 * (similarity_count / total_count))

    if verbosity:
        print("\tand it took", time.time() - pcap_starttime, 'seconds.')

    return percent_same

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
    filenames = []
    pcap_extensions = [
        '.pcapng', '.pcap', '.cap', '.dmp', '.5vw', '.TRC0', '.TRC1', '.enc',
        '.trc', '.fdc', '.syc', '.bfr', '.tr1', '.snoop'
    ]
    if args['--version']:
        print('PcapGraph v1.0.0\nLicense: Apache 2')
        sys.exit()

    filesizes = []
    for filename in args['<file>']:
        if not os.path.isfile(filename):
            print("ERROR:", filename, "not found!")
            sys.exit()
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in pcap_extensions:
            print("ERROR:", filename, "is not a valid packet capture!")
            print("Valid packet capture extensions:", pcap_extensions)
            sys.exit()
        filenames.append(filename)
        # Save size in MB
        filesizes.append(os.stat(filename).st_size / 10**6)

    if args['<file>']:
        # A 100MB file is ~ 100K packets. Lazy math indicates that
        # a billion packet-by-packet comparisons takes ~10s. If we reach an
        # expected 1 billion packet comparisons, let the user know.
        est_time = 0
        for filesize in filesizes:
            est_time += filesizes[0] * filesize
        if args['--compare']:  # Compare will double processing time.
            est_time *= 2
        if est_time > 1000:
            print("\nEstimated time to complete is greater than 10 seconds "
                  "(i.e. grab a cup of coffee).\n")

    return filenames


def get_tshark_status():
    """Errors and quits if tshark is not installed."""
    try:
        # tshark is not necessarily on path in Windows, even if installed.
        if sys.platform == 'win32':
            os.chdir('C:\\Program Files\\Wireshark')
        sp.Popen(['tshark', '-v'], stdout=sp.PIPE)
    except FileNotFoundError as err:
        print("ERROR: Requirement tshark from Wireshark is not satisfied!",
              "\n       Please download Wireshark and try again.\n\n",
              err)
        webbrowser.open('https://www.wireshark.org/download.html')
        sys.exit()


def get_pcap_data(filenames, has_compare_pcaps):
    """Return a dict with names of pcap files and their start/stop times.

    Args:
        filenames (list): A list of filepaths.
        has_compare_pcaps (bool): Has the user has provided the '-c' option.
    Return:
        (dict): A dict with all of the data that graph functions need.
    """
    pcap_data = {}
    # The pivot is compared against to see how much traffic is the same.
    pivot_pcap = filenames[0]
    if sys.platform == 'win32':
        # To use subprocess on windows, pass in a list of commands to Popen
        tshark_cmds = ['cmd', '/c', 'C:\\"Program Files"\\Wireshark\\tshark']
    else:
        tshark_cmds = ['tshark']

    for filename in filenames:
        packet_count_cmds = [*tshark_cmds, '-r', filename, '-2']
        pcap_text_raw = sp.Popen(packet_count_cmds, stdout=sp.PIPE)
        pcap_text = decode_stdout(pcap_text_raw)
        packet_count = pcap_text.count('\n')  # Each line of output is a packet.

        start_unixtime_cmds = [*tshark_cmds, '-r', filename,
                               '-2', '-Y', 'frame.number==1',
                               '-T', 'fields', '-e', 'frame.time_epoch']
        end_unixtime_cmds = [*tshark_cmds, '-r', filename,
                             '-2', '-Y', 'frame.number==' + str(packet_count),
                             '-T', 'fields', '-e', 'frame.time_epoch']
        pcap_start_raw = sp.Popen(start_unixtime_cmds, stdout=sp.PIPE)
        pcap_end_raw = sp.Popen(end_unixtime_cmds, stdout=sp.PIPE)
        pcap_start = decode_stdout(pcap_start_raw)
        pcap_end = decode_stdout(pcap_end_raw)

        filename_sans_path = os.path.splitext(os.path.basename(filename))[0]
        if has_compare_pcaps:
            pivot_file_similarity = get_pcap_similarity(pivot_pcap, filename)
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

    return pcap_data


def decode_stdout(stdout):
    """Given stdout, return the string."""
    return stdout.communicate()[0].decode('utf-8')


def get_pcap_similarity(pivot_pcap, other_pcap):
    """Compare the pivot pcap to another file.

    Take two packet captures and then compare each packet in one to each
    packet in the other by IP ID and other filters. Frames are not
    considered as there is no good way to verify that one frame is the same
    as another. FCS is discarded by the capturing device and is not
    present in packet captures.

    tshark produces two IP headers for ICMP packets. This is expected behavior.

    Args:
        pivot_pcap (string): Filename of the pivot pcap
        other_pcap (string): Filename of the pcap to compare to the privot pcap
    Return:
        (int) 1-3 digit percentage similarity between the two files
    """
    # Iterate over all packets with the given frame number.
    pcap_starttime = time.time()
    print("--compare percent similar is starting... ", end='')
    pivot_raw_output = subprocess.check_output(
        [
            'tshark -n -r ' + pivot_pcap + ' -2 -Y ip -T fields -e ip.id -e '
            'ip.src -e ip.dst -e tcp.ack -e tcp.seq -e udp.srcport'
        ],
        shell=True)
    pivot_pkts = set(str(pivot_raw_output.decode('utf8')).split('\n'))
    other_raw_output = subprocess.check_output(
        [
            'tshark -n -r ' + other_pcap + ' -2 -Y ip -T fields -e ip.id -e '
            'ip.src -e ip.dst -e tcp.ack -e tcp.seq -e udp.srcport'
        ],
        shell=True)
    other_pkts = set(str(other_raw_output.decode('utf8')).split('\n'))
    total_count = len(pivot_pkts)
    same_pkts = set(pivot_pkts).intersection(other_pkts)
    similarity_count = len(same_pkts)
    percent_same = round(100 * (similarity_count / total_count))
    print("and took", time.time() - pcap_starttime, 'seconds.')

    return percent_same

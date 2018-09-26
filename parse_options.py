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

import subprocess
import sys
import os


def parse_cli_args(args):
    """Parse args with docopt. Return a list of filenames"""
    filenames = []
    pcap_extensions = ['.pcapng', '.pcap', '.cap', '.dmp', '.5vw', '.TRC0',
                       '.TRC1', '.enc', '.trc', '.fdc', '.syc', '.bfr',
                       '.tr1', '.snoop']
    if args['--version']:
        print('PcapGraph v1.0.0\nLicense: Apache 2')
        sys.exit()

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

    return filenames


def get_tshark_status():
    """Errors and quits if tshark is not installed."""
    try:
        subprocess.check_output(['tshark -h'], shell=True)
    except subprocess.CalledProcessError as err:
        print("ERROR: tshark is not installed!", err)
        sys.exit()


def get_pcap_data(filenames):
    """Return a dict with names of pcap files and their start/stop times."""
    pcap_data = {}

    for filename in filenames:
        pkt_ct_cmd = 'tshark -r ' + filename + ' -2 | wc -l'
        packet_count = int(subprocess.check_output([pkt_ct_cmd], shell=True))
        start_unixtime_cmd = 'tshark -r ' + filename + ' -2 -Y frame.' \
            'number==1 -T fields -e frame.time_epoch'
        pcap_start = subprocess.check_output([start_unixtime_cmd], shell=True)
        end_unixtime_cmd = 'tshark -r ' + filename + ' -2 -Y frame.' \
            'number==' + str(packet_count) + ' -T fields -e frame.time_epoch'
        pcap_end = subprocess.check_output([end_unixtime_cmd], shell=True)

        filename_sans_path = os.path.splitext(os.path.basename(filename))[0]
        pcap_data[filename_sans_path] = {
            'packet_count': int(packet_count),
            'pcap_starttime': float(pcap_start),
            'pcap_endtime': float(pcap_end)
        }

    return pcap_data


"""
    unique_info = {}
    for packet in initial_packet_capture:
        unique_info[packet.ip.id] = packet.frame.time_epoch

    percent_same = {}
    for capture in captures:
        total_count = 0
        similarity_count = 0
        for packet in capture:
            for packet_info in unique_info:
                if packet.ip.id == packet_info and \
                        packet.frame.time_epoch == unique_info[packet_info]:
                    similarity_count += 1
            total_count += 1
        percent_same[pcap_name] = similarity_count / total_count
"""
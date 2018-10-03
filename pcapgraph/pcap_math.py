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
"""Do algebraic operations on sets like union, intersect, """

import subprocess as sp
import os


def pcap_intersector(pcap_names):
    """Save pcap intersection. First filename is pivot packet capture.

    Assume all traffic is seen at A and parts of A's traffic are seen at
    various other points. This works best with the following kind of scenario:
        There is an application that is sending traffic from a client to a
        server across the internet

    With that scenario in mind and given these sets,
    A = (1,2,3,4,5)
    B = (1,2,3)
    C = (2,3)
    D = (3,4)

    pcap_intersection([A, B, C, D]) produces package captures and percentages:
    intersection.pcap (3)   20%
    diff_A_B (4, 5)         60%
    diff_A_C (1, 4, 5)      40%
    diff_A_D (1, 2, 5)      40%

    Percentages indicate what percentage of BCD's packets are the same as A's.
    Files starting with 'diff' are set differences of all packets to pivot A.
    """


def framed_pcap_intersector(pcap1, pcap2, has_temporal_intersection):
    """Create a packet capture intersection out of two files using ipids.

    Let 2 packet captures have the following packets and assume that traffic
    originates behind the device that Pcap1 is capturing on:

    Pcap1                           Pcap2
    A                               W
    B                               X
    C                               A
    D                               B
    E                               F
    F                               M
    G                               C
    H                               G
    I                               L

    The algorithm would have found that packet A is the earliest common packet
    and that G is the latest common packet. The returned pcaps would like so:

    Pcap1                           Pcap2
    A                               A
    B                               B
    C                               F
    D                               M
    E                               C
    F                               G
    G

    NOTES
        * In Pcap2, M does not exist in Pcap1
        * In Pcap2, F is out of order compared to Pcap1

    Create a packet capture by finding the earliest common packet by and
    then the latest common packet in both pcaps by ip.id. Then return


    Args:
        pcap1 (string): Filename of packet capture 1.
        pcap2 (string): Filename of packet capture 2.
    """
    # Init vars
    pcap_info = {
        pcap1: [],
        pcap2: []
    }
    # TODO replace with get_tshark_status
    os.environ["PATH"] += os.pathsep + os.pathsep.join(
        ["C:\\Program Files\\Wireshark"])

    # Get a list of sequential ip ids from both packet captures
    for pcap in (pcap1, pcap2):
        get_pcap1_ipids = ['tshark', '-r', pcap, '-T', 'fields',
                           '-e', 'frame.number', '-e', 'ip.id']
        pcap_raw = sp.Popen(get_pcap1_ipids, stdout=sp.PIPE, stderr=sp.PIPE)
        # output should be of the form "frame.number\tip.id\r\n" per packet.
        pcap_output = pcap_raw.communicate()[0].decode('utf8')
        # Split by newline and remove last value, which will be ''
        pcap_packet_list = pcap_output.split('\r\n')[:-1]
        for packet in pcap_packet_list:
            frame_num, ip_id = packet.split('\t')
            # Every frame number should be present as we iterate through packets
            pcap_info[pcap].append(ip_id)

    # Using index instead of dictionary element because in Python 3.6,
    # dict element order is not guaranteed to be the same as insertion order.
    pcap1_first_common_frame, pcap2_first_common_frame = \
        search_for_common_frame(pcap_info[pcap1], pcap_info[pcap2])
    pcap1_last_frame, pcap2_last_frame = search_for_common_frame(
        list(reversed(pcap_info[pcap1])), list(reversed(pcap_info[pcap2])))
    pcap1_last_common_frame = len(pcap_info[pcap1]) - pcap1_last_frame + 1
    pcap2_last_common_frame = len(pcap_info[pcap2]) - pcap2_last_frame + 1

    pcap1_name = str(os.path.basename(pcap1).split('.pcap')[0])
    pcap2_name = str(os.path.basename(pcap2).split('.pcap')[0])

    if has_temporal_intersection:
        pcap1_outname = pcap1_name + '-framed_intersect_with-' + pcap2_name + \
            '.pcap'
        pcap2_outname = pcap2_name + '-framed_intersect_with-' + pcap1_name + \
            '.pcap'

        pcap1_intersect_cmds = [
            'tshark', '-r', pcap1, '-Y', 'frame.number>=' + str(
                pcap1_first_common_frame)
            + ' and frame.number <= ' + str(pcap1_last_common_frame), '-w',
            pcap1_outname]
        pcap2_intersect_cmds = [
            'tshark', '-r', pcap2, '-Y', 'frame.number>=' + str(
                pcap2_first_common_frame) + ' and frame.number<=' + str(
                pcap2_last_common_frame), '-w',
            pcap2_outname]

        framed_pcap_cmds = {
            pcap1: pcap1_intersect_cmds,
            pcap2: pcap2_intersect_cmds
        }
        # Write both files
        for pcap in (pcap1, pcap2):
            sp.Popen(framed_pcap_cmds[pcap])
    else:
        """
        The logic that needs to go here:
        A dict that has this info on each packet:
            - protocols > find bpf 
            - ip.ids 
            - ip.checksum
            - ip.src
            - ip.dst
            - tcp.ack
            - tcp.seq
            - srcport 
            - dstport  
            - udp.checksum > find bpf
            - tcp.checksum > find bpf
            
        1. Add all packet data to one dict per pcap
        2. Get the intersection set() of both dicts 
        3. From pcap1, filter for exactly what's left in the dict and 
            save it as the intersection
        """
        outname = pcap1_name + '-' + pcap2_name + '_intersection.pcap'
        intersection_commands
        # Write one intersection
        for pcap in (pcap1, pcap2):
            sp.Popen(framed_pcap_cmds[pcap])


def search_for_common_frame(frame_list1, frame_list2):
    """Search for a common frame by iterating through list1 and then list2.

    To search the list in reverse, pass in a reversed list.

    Args:
        frame_list1 (list): List of ip_ids from pcap1
        frame_list2 (list): List of ip_ids from pcap2
    Returns:
        (tuple(int)): Frame numbers of first found common frame.
    """
    for pcap1_index, _ in enumerate(frame_list1):
        print(pcap1_index)
        pcap1_packet_ip_id = frame_list1[pcap1_index]
        for pcap2_index, _ in enumerate(frame_list2):
            print(pcap2_index)
            pcap2_packet_ip_id = frame_list2[pcap2_index]
            if pcap1_packet_ip_id == pcap2_packet_ip_id:
                return pcap1_index + 1, pcap2_index + 1

framed_pcap_intersector('examples/simul1.pcap', 'examples/simul2.pcap')

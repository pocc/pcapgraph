#!/usr/bin/env python3
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
"""Script to create three packet captures to demonstrate PcapGraph."""
import time
import sys
import subprocess


def generate_example_pcaps():
    """This script will create 3 packet captures, each lasting 60 seconds and
    starting at 0s, 20s, 40s. After 100s, this script will stop. Packet
    capture 0s should have 66% in common with pcap 20s and 33% in common
    with pcap 40s. Indeed, this is what we see in the graph.

    Shell must be true so that Popen sends these processes to the background.
    """
    second_ct = 0
    tshark_cmd = 'tshark -n -f "icmp or port 53" -a duration:60 '

    if sys.platform == 'win32':
        ping_once_flag = '-n 1'
    else:
        ping_once_flag = '-c 1'

    while second_ct < 100:
        print('On second ' + str(second_ct + 1) + '/100')
        subprocess.Popen(['ping 8.8.8.8 ' + ping_once_flag], shell=True)
        subprocess.Popen(['nslookup amazon.com'], shell=True)
        if second_ct == 0:
            subprocess.Popen([tshark_cmd + '-w simul1.pcap'], shell=True)
        if second_ct == 20:
            subprocess.Popen([tshark_cmd + '-w simul2.pcap'], shell=True)
        if second_ct == 40:
            subprocess.Popen([tshark_cmd + '-w simul3.pcap'], shell=True)
        time.sleep(1)
        second_ct += 1

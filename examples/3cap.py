#!/usr/bin/env python3
# -*- coding:utf8 -*-
"""Script to create three packet captures to demonstrate PcapGraph.

This script will create 3 packet captures, each lasting 60 seconds and
starting at 0s, 20s, 40s. After 100s, this script will stop."""
import time
import sys
import subprocess

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

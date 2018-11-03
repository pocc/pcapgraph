#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""Shared vars/functions for test classes."""

import os

from pcapgraph import get_tshark_status


def setup_testenv():
    """Set up PATH and current working directory."""
    get_tshark_status()
    # If testing from ./tests, change to root directory (useful in PyCharm)
    if os.getcwd().endswith('tests'):
        os.chdir('..')


DEFAULT_CLI_ARGS = {
    '--anonymize': False,
    '--bounded-intersection': False,
    '--difference': False,
    '--exclude-empty': False,
    '--help': False,
    '--intersection': False,
    '--inverse-bounded': False,
    '--output': [],
    '--strip-l2': False,
    '--strip-l3': False,
    '--symmetric-difference': False,
    '--union': False,
    '--verbose': False,
    '--version': False,
    '-w': False,
    '<file>': [],
}

EXPECTED_UNION_STDOUT = """Count: 3      
0000  88 15 44 ab bf dd 24 77 03 51 13 44 08 00 45 00
0010  00 54 7b af 40 00 40 01 92 2a 0a 30 12 90 08 08
0020  08 08 08 00 ae 46 62 8b 00 01 e8 30 ab 5b 00 00
0030  00 00 88 cd 0c 00 00 00 00 00 10 11 12 13 14 15
0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
0060  36 37              

Count: 3      
0000  88 15 44 ab bf dd 24 77 03 51 13 44 08 00 45 00
0010  00 38 20 40 00 00 40 11 b2 b5 0a 30 12 90 0a 80
0020  80 80 ba dc 00 35 00 24 cb 35 a3 f6 01 00 00 01
0030  00 00 00 00 00 00 06 61 6d 61 7a 6f 6e 03 63 6f
0040  6d 00 00 01 00 01          

Count: 3      
0000  24 77 03 51 13 44 88 15 44 ab bf dd 08 00 45 00
0010  00 68 f7 f9 40 00 40 11 9a cb 0a 80 80 80 0a 30
0020  12 90 00 35 ba dc 00 54 1e c2 a3 f6 81 80 00 01
0030  00 03 00 00 00 00 06 61 6d 61 7a 6f 6e 03 63 6f
0040  6d 00 00 01 00 01 c0 0c 00 01 00 01 00 00 00 15
0050  00 04 b0 20 67 cd c0 0c 00 01 00 01 00 00 00 15
0060  00 04 cd fb f2 67 c0 0c 00 01 00 01 00 00 00 15
0070  00 04 b0 20 62 a6          

Count: 3      
0000  24 77 03 51 13 44 88 15 44 ab bf dd 08 00 45 20
0010  00 54 ef c6 00 00 79 01 24 f3 08 08 08 08 0a 30
0020  12 90 00 00 b6 46 62 8b 00 01 e8 30 ab 5b 00 00
0030  00 00 88 cd 0c 00 00 00 00 00 10 11 12 13 14 15
0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
0060  36 37              

Count: 3      
0000  88 15 44 ab bf dd 24 77 03 51 13 44 08 00 45 00
0010  00 54 7b fa 40 00 40 01 91 df 0a 30 12 90 08 08
0020  08 08 08 00 74 29 62 93 00 01 e9 30 ab 5b 00 00
0030  00 00 c1 e2 0c 00 00 00 00 00 10 11 12 13 14 15
0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
0060  36 37              

Count: 3      
0000  88 15 44 ab bf dd 24 77 03 51 13 44 08 00 45 00
0010  00 38 20 8b 00 00 40 11 b2 6a 0a 30 12 90 0a 80
0020  80 80 ea ea 00 35 00 24 69 94 d5 89 01 00 00 01
0030  00 00 00 00 00 00 06 61 6d 61 7a 6f 6e 03 63 6f
0040  6d 00 00 01 00 01          

Count: 3      
0000  24 77 03 51 13 44 88 15 44 ab bf dd 08 00 45 00
0010  00 68 f7 fc 40 00 40 11 9a c8 0a 80 80 80 0a 30
0020  12 90 00 35 ea ea 00 54 bd 23 d5 89 81 80 00 01
0030  00 03 00 00 00 00 06 61 6d 61 7a 6f 6e 03 63 6f
0040  6d 00 00 01 00 01 c0 0c 00 01 00 01 00 00 00 14
0050  00 04 b0 20 62 a6 c0 0c 00 01 00 01 00 00 00 14
0060  00 04 b0 20 67 cd c0 0c 00 01 00 01 00 00 00 14
0070  00 04 cd fb f2 67          

Count: 3      
0000  24 77 03 51 13 44 88 15 44 ab bf dd 08 00 45 20
0010  00 54 f1 7a 00 00 79 01 23 3f 08 08 08 08 0a 30
0020  12 90 00 00 7c 29 62 93 00 01 e9 30 ab 5b 00 00
0030  00 00 c1 e2 0c 00 00 00 00 00 10 11 12 13 14 15
0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
0060  36 37              

Count: 3      
0000  88 15 44 ab bf dd 24 77 03 51 13 44 08 00 45 00
0010  00 54 7c 4e 40 00 40 01 91 8b 0a 30 12 90 08 08
0020  08 08 08 00 8e 09 62 9f 00 01 ea 30 ab 5b 00 00
0030  00 00 a6 f6 0c 00 00 00 00 00 10 11 12 13 14 15
0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
0060  36 37              

To view the content of these packets, subtract the count lines,
add and save to <textfile>, and then run 

text2pcap <textfile> out.pcap
wireshark out.pcap

"""

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

SINGLE_FRAME_JSON = {'_index': 'packets-2018-11-03', '_type': 'pcap_file', '_score': None, '_source': {'layers': {'frame_raw': ['881544abbfdd2477035113440800450000380b5d00004011c7980a3012900a808080ea6200350024a4929b130100000100000000000006616d617a6f6e03636f6d0000010001', 0, 70, 0, 1], 'frame': {'frame.encap_type': '1', 'frame.time': 'Sep 26, 2018 00:09:52.655360000 PDT', 'frame.offset_shift': '0.000000000', 'frame.time_epoch': '1537945792.655360000', 'frame.time_delta': '0.000000000', 'frame.time_delta_displayed': '0.000000000', 'frame.time_relative': '0.000000000', 'frame.number': '1', 'frame.len': '70', 'frame.cap_len': '70', 'frame.marked': '0', 'frame.ignored': '0', 'frame.protocols': 'eth:ethertype:ip:udp:dns'}, 'eth_raw': ['881544abbfdd2477035113440800', 0, 14, 0, 1], 'eth': {'eth.dst_raw': ['881544abbfdd', 0, 6, 0, 29], 'eth.dst': '88:15:44:ab:bf:dd', 'eth.dst_tree': {'eth.dst_resolved_raw': ['881544abbfdd', 0, 6, 0, 26], 'eth.dst_resolved': 'CiscoMer_ab:bf:dd', 'eth.addr_raw': ['881544abbfdd', 0, 6, 0, 29], 'eth.addr': '88:15:44:ab:bf:dd', 'eth.addr_resolved_raw': ['881544abbfdd', 0, 6, 0, 26], 'eth.addr_resolved': 'CiscoMer_ab:bf:dd', 'eth.lg_raw': ['0', 0, 3, 131072, 2], 'eth.lg': '0', 'eth.ig_raw': ['0', 0, 3, 65536, 2], 'eth.ig': '0'}, 'eth.src_raw': ['247703511344', 6, 6, 0, 29], 'eth.src': '24:77:03:51:13:44', 'eth.src_tree': {'eth.src_resolved_raw': ['247703511344', 6, 6, 0, 26], 'eth.src_resolved': 'IntelCor_51:13:44', 'eth.addr_raw': ['247703511344', 6, 6, 0, 29], 'eth.addr': '24:77:03:51:13:44', 'eth.addr_resolved_raw': ['247703511344', 6, 6, 0, 26], 'eth.addr_resolved': 'IntelCor_51:13:44', 'eth.lg_raw': ['0', 6, 3, 131072, 2], 'eth.lg': '0', 'eth.ig_raw': ['0', 6, 3, 65536, 2], 'eth.ig': '0'}, 'eth.type_raw': ['0800', 12, 2, 0, 5], 'eth.type': '0x00000800'}, 'ip_raw': ['450000380b5d00004011c7980a3012900a808080', 14, 20, 0, 1], 'ip': {'ip.version_raw': ['4', 14, 1, 240, 4], 'ip.version': '4', 'ip.hdr_len_raw': ['45', 14, 1, 0, 4], 'ip.hdr_len': '20', 'ip.dsfield_raw': ['00', 15, 1, 0, 4], 'ip.dsfield': '0x00000000', 'ip.dsfield_tree': {'ip.dsfield.dscp_raw': ['0', 15, 1, 252, 4], 'ip.dsfield.dscp': '0', 'ip.dsfield.ecn_raw': ['0', 15, 1, 3, 4], 'ip.dsfield.ecn': '0'}, 'ip.len_raw': ['0038', 16, 2, 0, 5], 'ip.len': '56', 'ip.id_raw': ['0b5d', 18, 2, 0, 5], 'ip.id': '0x00000b5d', 'ip.flags_raw': ['0000', 20, 2, 0, 5], 'ip.flags': '0x00000000', 'ip.flags_tree': {'ip.flags.rb_raw': ['0', 20, 2, 32768, 2], 'ip.flags.rb': '0', 'ip.flags.df_raw': ['0', 20, 2, 16384, 2], 'ip.flags.df': '0', 'ip.flags.mf_raw': ['0', 20, 2, 8192, 2], 'ip.flags.mf': '0', 'ip.frag_offset_raw': ['0', 20, 2, 8191, 5], 'ip.frag_offset': '0'}, 'ip.ttl_raw': ['40', 22, 1, 0, 4], 'ip.ttl': '64', 'ip.proto_raw': ['11', 23, 1, 0, 4], 'ip.proto': '17', 'ip.checksum_raw': ['c798', 24, 2, 0, 5], 'ip.checksum': '0x0000c798', 'ip.checksum.status': '2', 'ip.src_raw': ['0a301290', 26, 4, 0, 32], 'ip.src': '10.48.18.144', 'ip.addr_raw': ['0a808080', 30, 4, 0, 32], 'ip.addr': '10.128.128.128', 'ip.src_host_raw': ['0a301290', 26, 4, 0, 26], 'ip.src_host': '10.48.18.144', 'ip.host_raw': ['0a808080', 30, 4, 0, 26], 'ip.host': '10.128.128.128', 'ip.dst_raw': ['0a808080', 30, 4, 0, 32], 'ip.dst': '10.128.128.128', 'ip.dst_host_raw': ['0a808080', 30, 4, 0, 26], 'ip.dst_host': '10.128.128.128'}, 'udp_raw': ['ea6200350024a492', 34, 8, 0, 1], 'udp': {'udp.srcport_raw': ['ea62', 34, 2, 0, 5], 'udp.srcport': '60002', 'udp.dstport_raw': ['0035', 36, 2, 0, 5], 'udp.dstport': '53', 'udp.port_raw': ['0035', 36, 2, 0, 5], 'udp.port': '53', 'udp.length_raw': ['0024', 38, 2, 0, 5], 'udp.length': '36', 'udp.checksum_raw': ['a492', 40, 2, 0, 5], 'udp.checksum': '0x0000a492', 'udp.checksum.status': '2', 'udp.stream': '0'}, 'dns_raw': ['9b130100000100000000000006616d617a6f6e03636f6d0000010001', 42, 28, 0, 1], 'dns': {'dns.id_raw': ['9b13', 42, 2, 0, 5], 'dns.id': '0x00009b13', 'dns.flags_raw': ['0100', 44, 2, 0, 5], 'dns.flags': '0x00000100', 'dns.flags_tree': {'dns.flags.response_raw': ['0', 44, 2, 32768, 2], 'dns.flags.response': '0', 'dns.flags.opcode_raw': ['0', 44, 2, 30720, 5], 'dns.flags.opcode': '0', 'dns.flags.truncated_raw': ['0', 44, 2, 512, 2], 'dns.flags.truncated': '0', 'dns.flags.recdesired_raw': ['1', 44, 2, 256, 2], 'dns.flags.recdesired': '1', 'dns.flags.z_raw': ['0', 44, 2, 64, 2], 'dns.flags.z': '0', 'dns.flags.checkdisable_raw': ['0', 44, 2, 16, 2], 'dns.flags.checkdisable': '0'}, 'dns.count.queries_raw': ['0001', 46, 2, 0, 5], 'dns.count.queries': '1', 'dns.count.answers_raw': ['0000', 48, 2, 0, 5], 'dns.count.answers': '0', 'dns.count.auth_rr_raw': ['0000', 50, 2, 0, 5], 'dns.count.auth_rr': '0', 'dns.count.add_rr_raw': ['0000', 52, 2, 0, 5], 'dns.count.add_rr': '0', 'Queries': {'amazon.com: type A, class IN': {'dns.qry.name_raw': ['06616d617a6f6e03636f6d00', 54, 12, 0, 26], 'dns.qry.name': 'amazon.com', 'dns.qry.name.len_raw': ['06616d617a6f6e03636f', 54, 10, 0, 5], 'dns.qry.name.len': '10', 'dns.count.labels_raw': ['06616d617a6f6e03636f', 54, 10, 0, 5], 'dns.count.labels': '2', 'dns.qry.type_raw': ['0001', 66, 2, 0, 5], 'dns.qry.type': '1', 'dns.qry.class_raw': ['0001', 68, 2, 0, 5], 'dns.qry.class': '0x00000001'}}}}}}

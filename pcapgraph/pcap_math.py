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
"""Do algebraic operations on sets like union, intersect, difference."""
import collections
import os
import time

from pcapgraph.manipulate_frames import parse_pcaps
from pcapgraph.manipulate_frames import get_flat_frame_dict
from pcapgraph.manipulate_frames import get_frame_list_by_pcap
from pcapgraph.manipulate_frames import get_frame_from_json
from pcapgraph.save_file import convert_to_pcaptext
import pcapgraph.save_file as save


class PcapMath:
    """Do algebraic operations on sets like union, intersect, difference.

    For multiple set operations, files are read in only once in __init__.
    Use different PcapMath objects if input files are different.
    """

    def __init__(self, filenames, options):
        """Prepare PcapMath object for one or multiple operations.

        Every PcapMath object should start with the data structures filled with
        the data that each operation needs to function.

        Args:
            filenames (list): List of filenames.
            options (dict): Whether to strip L2 and L3 headers.
        """
        self.filenames = filenames
        self.pcap_json_dict = {}
        for file in filenames:
            pcap_json = parse_pcaps([file])[0]
            if options['strip-l3']:
                for index, packet in enumerate(pcap_json):
                    ip_raw = packet['_source']['layers']['ip_raw']
                    frame_raw = packet['_source']['layers']['frame_raw']
                    homogenized_packet = self.homogenize_l3_header(ip_raw)
                    pcap_json[index]['_source']['layers']['frame_raw'] = \
                        homogenized_packet + frame_raw.split(ip_raw)[1]
            elif options['strip-l2']:
                for index, packet in enumerate(pcap_json):
                    eth_raw = packet['_source']['layers']['eth_raw']
                    eth_len = len(eth_raw)
                    frame_raw = packet['_source']['layers']['frame_raw']
                    pcap_json[index]['_source']['layers']['frame_raw'] = \
                        frame_raw[eth_len:]
            self.pcap_json_dict[file] = pcap_json

        pcap_json_list = [*self.pcap_json_dict.values()]
        self.frame_timestamp_dict = get_flat_frame_dict(pcap_json_list)
        self.frame_list_by_pcap = []
        self.exclude_empty = False
        self.options = options

    @staticmethod
    def homogenize_l3_header(ip_raw):
        """Replace TTL, header checksum, and IP src/dst with generic values.

        This function is designed to replace all IP data that would change on
        a layer 3 boundary

        Note that these options are found only in IPv4.
        TTL is expected to change at every hop along with header
        checksum. IPs are expected to change for NAT.

        Args:
            ip_raw (str): The IP header per RFC 791.
        Returns:
            (str): The modified packet that contains more generic values.
        """
        ttl = 'ff'
        ip_proto = ip_raw[18:20]
        ip_checksum = '1337'
        src_ip = '0a010101'
        dst_ip = '0a020202'
        modified_packet = ip_raw[:16] + ttl + ip_proto + \
            ip_checksum + src_ip + dst_ip + ip_raw[40:]
        return modified_packet

    def parse_set_args(self, args):
        """Call the appropriate method per CLI flags.

        difference, union, intersect consist of {<op>: {frame: timestamp, ...}}
        bounded_intersect consists of {pcap: {frame: timestamp, ...}, ...}

        Args:
            args (dict): Dict of all arguments (including set args).
        """
        new_files = []
        bounded_filelist = []
        self.exclude_empty = args['--exclude-empty']
        if args['--difference']:
            generated_file = self.difference_pcap()
            # As long as the difference exists and .
            if generated_file and not args['--exclude-empty']:
                new_files.append(generated_file)
        if args['--intersection']:
            generated_file = self.intersect_pcap()
            new_files.append(generated_file)
        if args['--symmetric-difference']:
            generated_filelist = self.symmetric_difference_pcap()
            new_files.extend(generated_filelist)
        if args['--union']:
            generated_file = self.union_pcap()
            new_files.append(generated_file)

        if args['--bounded-intersection']:
            bounded_filelist = self.bounded_intersect_pcap()
            new_files.extend(bounded_filelist)
        if args['--inverse-bounded']:
            generated_filelist = self.inverse_bounded_intersect_pcap(
                bounded_filelist=bounded_filelist)
            new_files.extend(generated_filelist)

        # Put filenames in a different place in memory so it is not altered.
        filenames = list(self.filenames)
        filenames.extend(new_files)
        return filenames

    def union_pcap(self):
        """Given sets A = (1, 2, 3), B = (2, 3, 4), A + B = (1, 2, 3, 4).

        About:
            This method uses tshark to get identifying information on
            pcaps and then mergepcap to save the combined pcap.

        Returns:
            (string): Name of generated pcap.
        """
        raw_packet_list = []
        for pcap in self.pcap_json_dict.values():
            for frame in pcap:
                raw_frame = get_frame_from_json(frame)
                raw_packet_list.append(raw_frame)

        self.print_10_most_common_frames(raw_packet_list)

        union_frame_dict = {}
        for frame in raw_packet_list:
            union_frame_dict[frame] = self.frame_timestamp_dict[frame]
        save.save_pcap(
            pcap_dict=union_frame_dict,
            name='union.pcap',
            options=self.options)

        return 'union.pcap'

    @staticmethod
    def print_10_most_common_frames(raw_packet_list):
        """After doing a packet union, find/print the 10 most common packets.

        This is a work in progress and may eventually use this bash:

        <packets> | text2pcap - - | tshark -r - -o 'gui.column.format:"No.",
        "%m","VLAN","%q","Src MAC","%uhs","Dst MAC","%uhd","Src IP","%us",
        "Dst IP","%ud","Protocol","%p","Src port","%uS","Dst port","%uD"'

        Alternatively, just use the existing information in pcap_dict.

        The goal is to print
        frame#, VLAN, src/dst MAC, src/dst IP, L4 src/dst ports, protocol

        This should likely be its own CLI flag in future.
        """
        packet_stats = collections.Counter(raw_packet_list)
        # It's not a common frame if it is only seen once.
        packet_stats = {k: v for k, v in packet_stats.items() if v > 1}
        sorted_packets = sorted(
            packet_stats, key=packet_stats.__getitem__, reverse=True)
        counter = 0
        for packet in sorted_packets:
            counter += 1
            if counter == 10:
                break
            packet_text = convert_to_pcaptext(packet)

            print("Count: {: <7}\n{: <}".format(packet_stats[packet],
                                                packet_text))
        print("To view the content of these packets, subtract the count lines,"
              "\nadd and save to <textfile>, and then run "
              "\n\ntext2pcap <textfile> out.pcap\nwireshark out.pcap\n")

    def intersect_pcap(self):
        """Save pcap intersection. First filename is pivot packet capture.

        Returns:
            (string): Name of generated pcap.
        """
        # Generate intersection set of frames
        if not self.frame_list_by_pcap:
            self.frame_list_by_pcap = \
                get_frame_list_by_pcap(self.pcap_json_dict)
        frame_list = self.frame_list_by_pcap
        frame_intersection = set(frame_list[0]).intersection(*frame_list[1:])

        # Print intersection output like in docstring
        intersection_count = len(frame_intersection)
        print("{: <12} {: <}".format('\nSAME %', 'PCAP NAME'))
        for pcap in self.filenames:
            same_percent = str(
                round(100 * (intersection_count / len(frame_list[0])))) + '%'
            print("{: <12} {: <}".format(same_percent, pcap))

        intersect_frame_dict = {}
        for frame in frame_intersection:
            intersect_frame_dict[frame] = self.frame_timestamp_dict[frame]
        save.save_pcap(
            pcap_dict=intersect_frame_dict,
            name='intersect.pcap',
            options=self.options)

        if frame_intersection:
            return 'intersect.pcap'
        print('WARNING! Intersection between ', self.filenames,
              ' contains no packets!')
        return ''

    def difference_pcap(self, pivot_index=0):
        """Given sets A = (1, 2, 3), B = (2, 3, 4), C = (3, 4, 5), A-B-C = (1).

        Args:
            pivot_index [int]: Specify minuend by index of filename in list

        Returns:
            (string): Name of generated pcap.
        """
        pcap_json_list = [*self.pcap_json_dict.values()]
        minuend_pcap_json = pcap_json_list[pivot_index]
        minuend_name = self.filenames[pivot_index]
        # pcap json list - minuend json. With index 0, remove 1st pcap json.
        diff_pcap_json_list = pcap_json_list[:pivot_index] + \
            pcap_json_list[pivot_index+1:]

        minuend_frame_dict = get_flat_frame_dict([minuend_pcap_json])
        minuend_frame_list = list(minuend_frame_dict.keys())
        diff_frame_dict = get_flat_frame_dict(diff_pcap_json_list)
        diff_frame_list = list(diff_frame_dict.keys())
        packet_diff = set(minuend_frame_list).difference(set(diff_frame_list))

        diff_frame_dict = {}
        for frame in packet_diff:
            # Minuend frame dict should have all values we care about.
            diff_frame_dict[frame] = minuend_frame_dict[frame]
        diff_filename = 'diff_' + os.path.basename(minuend_name)
        # Save only if there are packets or -x flag is not used.
        if not packet_diff:
            print('WARNING! ' + minuend_name +
                  ' difference contains no packets!')
        if packet_diff or not self.exclude_empty:
            # If the file already exists, choose a different name.
            unique_diff_name = diff_filename
            while os.path.isfile(unique_diff_name):
                unique_diff_name = diff_filename[:-5] + '-' + \
                                   str(int(time.time())) + '.pcap'
            save.save_pcap(
                pcap_dict=diff_frame_dict,
                name=unique_diff_name,
                options=self.options)
            return unique_diff_name

        return ''

    def symmetric_difference_pcap(self):
        """For sets A = (1, 2, 3), B = (2, 3, 4), C = (3, 4, 5), A△B△C = (1, 5)

        For all pcaps, the symmetric difference produces a pcap that has the
        packets that are unique to only that pcap (unlike above where only one
        set is the result).

        Returns:
            (list(str)): Name of generated pcaps.
        """
        generated_filelist = []
        for index, file in enumerate(self.filenames):
            diff_filename = self.difference_pcap(pivot_index=index)
            if diff_filename:  # If diff file has packets.
                symdiff_filename = 'symdiff_' + os.path.basename(file)
                os.replace(diff_filename, symdiff_filename)
                generated_filelist.append(symdiff_filename)

        return generated_filelist

    def bounded_intersect_pcap(self):
        """Create a packet capture intersection out of two files using ip.ids.

        Create a packet capture by finding the earliest common packet by and
        then the latest common packet in both pcaps by ip.id.

        Returns:
            (list(string)): List of generated pcaps.
        """
        # Init vars
        bounded_pcaps = self.get_bounded_pcaps()
        names = []  # Names of all generated pcaps
        for index, _ in enumerate(bounded_pcaps):
            names.append('bounded_intersect-simul' + str(index + 1) + '.pcap')
            save.save_pcap(
                pcap_dict=bounded_pcaps[index],
                name=names[index],
                options=self.options)

        return names

    def inverse_bounded_intersect_pcap(self, bounded_filelist=False):
        """Inverse of bounded intersection = (bounded intersect) - (intersect)

        Args:
            bounded_filelist (list): List of existing bounded pcaps generated
                by bounded_intersect_pcap()
        Returns:
            List of files generated by this method.
        """
        generated_filelist = []
        has_bounded_intersect_flag = False
        if not bounded_filelist:
            # Don't generate twice if flags -be are used
            # Note that this runs after bounded_intersect if it would be run
            bounded_filelist = self.bounded_intersect_pcap()
            has_bounded_intersect_flag = True
        intersect_file = [self.intersect_pcap()]
        backup_filenames = self.filenames
        self.filenames = intersect_file
        for index, bi_file in enumerate(bounded_filelist):
            difference_file = self.difference_pcap(pivot_index=index)
            if difference_file:
                generated_filelist.append(difference_file)
            if has_bounded_intersect_flag:
                # Do not keep bounded-intersect files if they are not necessary
                os.remove(bi_file)
        self.filenames = backup_filenames
        return generated_filelist

    def get_bounded_pcaps(self):
        """Get the pcap frame list for bounded_intersect_pcap

        Create a bounding box around each packet capture where the bounds are
        the min and max packets in the intersection.

        Returns:
            bounded_pcaps: A list of frame_dicts
        """
        min_frame, max_frame = self.get_minmax_common_frames()

        bounded_pcaps = []
        # Each frame_list corresponds to one pcap.
        for frame_list in self.frame_list_by_pcap:
            min_frame_index = -1
            max_frame_index = -1
            for frame in frame_list:
                if frame == min_frame:
                    min_frame_index = frame_list.index(frame)
                    break
            if min_frame_index == -1:
                print("ERROR: Bounding minimum packet not found!")
                raise IndexError
            for frame in reversed(frame_list):
                if frame == max_frame:
                    max_frame_index = frame_list.index(frame)
                    break
            if max_frame_index == -1:
                print("ERROR: Bounding maximum packet not found!")
                raise IndexError

            bounded_frame_list = \
                frame_list[min_frame_index:max_frame_index + 1]
            bounded_pcap_with_timestamps = {}
            for frame in bounded_frame_list:
                bounded_pcap_with_timestamps[frame] = \
                    self.frame_timestamp_dict[frame]
            bounded_pcaps.append(bounded_pcap_with_timestamps)

        return bounded_pcaps

    def get_minmax_common_frames(self):
        """Get first, last frames of intersection pcap.

        Returns:
            min_frame, max_frame (tuple(string)):
                Packet strings of the packets that are at the beginning and end
                of the intersection pcap based on timestamps.
        Raises:
            assert: If intersection is empty.
        """
        # Generate intersection set of frames
        if not self.frame_list_by_pcap:
            self.frame_list_by_pcap = \
                get_frame_list_by_pcap(self.pcap_json_dict)
        frame_list = self.frame_list_by_pcap
        frame_intersection = set(frame_list[0]).intersection(*frame_list[1:])

        # Set may reorder packets, so search for first/last.
        unix_32bit_end_of_time = 4294967296
        time_min = unix_32bit_end_of_time
        time_max = 0
        max_frame = ''
        min_frame = ''
        for frame in frame_intersection:
            frame_time = float(self.frame_timestamp_dict[frame])
            if frame_time > time_max:
                time_max = frame_time
                max_frame = frame
            if frame_time < time_min:
                time_min = frame_time
                min_frame = frame

        # If min/max frames are '', that likely means the intersection is empty
        assert max_frame != ''
        assert min_frame != ''

        return min_frame, max_frame

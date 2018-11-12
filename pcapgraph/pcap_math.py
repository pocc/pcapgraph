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

from pcapgraph.manipulate_frames import strip_layers
from pcapgraph.manipulate_frames import get_frametext_from_files
from pcapgraph.save_file import get_canonical_hex_from_frametext
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
        pcap_frame_list = get_frametext_from_files(filenames)
        self.pcap_frame_list = strip_layers(pcap_frame_list, options)
        self.frame_list = []  # Flat ordered list of all frames
        self.timestamp_list = []  # Flat ordered list of all timestamps
        for pcap in self.pcap_frame_list:
            self.frame_list += self.pcap_frame_list[pcap]['frames']
            self.timestamp_list += self.pcap_frame_list[pcap]['timestamps']
        self.frame_list = list(filter(None, self.frame_list))
        self.timestamp_list = list(filter(None, self.timestamp_list))
        self.frame_timestamp_dict = {
            k: v
            for k, v in zip(self.frame_list, self.timestamp_list)
        }
        self.exclude_empty = False
        self.options = options

    def parse_set_args(self, args):
        """Call the appropriate method per CLI flags.

        difference, union, intersect consist of {<op>: {frame: timestamp, ...}}
        bounded_intersect consists of {pcap: {frame: timestamp, ...}, ...}

        Args:
            args (dict): Dict of all arguments (including set args).
        Returns:
            filenames (list): List of all files, including ones generated
                by set operations.
        """
        new_files = []
        bounded_filelist = []
        intersect_file = ''
        self.exclude_empty = args['--exclude-empty']
        if args['--difference']:
            generated_file = self.difference_pcap()
            # As long as the difference exists.
            if generated_file:
                new_files.append(generated_file)
        if args['--intersection']:
            intersect_file = self.intersect_pcap()
            new_files.append(intersect_file)
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
            if not intersect_file:
                intersect_file = self.intersect_pcap()
            generated_filelist = self.inverse_bounded_intersect_pcap(
                bounded_filelist=bounded_filelist,
                intersect_file=intersect_file)
            if not args['--intersection']:
                os.remove(intersect_file)
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
        self.print_10_most_common_frames(self.frame_list)

        union_frame_dict = {}
        for index, frame in enumerate(self.frame_list):
            union_frame_dict[frame] = self.timestamp_list[index]
        save.save_pcap(
            pcap_dict=union_frame_dict,
            name='union.pcap',
            options=self.options)

        return 'union.pcap'

    @staticmethod
    def print_10_most_common_frames(raw_frame_list):
        """After doing a packet union, find/print the 10 most common packets.

        This is a work in progress and may eventually use this bash:

        <packets> | text2pcap - - | tshark -r - -o 'gui.column.format:"No.",
        "%m","VLAN","%q","Src MAC","%uhs","Dst MAC","%uhd","Src IP","%us",
        "Dst IP","%ud","Protocol","%p","Src port","%uS","Dst port","%uD"'

        Alternatively, just use the existing information in pcap_dict.

        The goal is to print
        frame#, VLAN, src/dst MAC, src/dst IP, L4 src/dst ports, protocol

        This should likely be its own CLI flag in future.

        Args:
            raw_frame_list (list): List of raw frames
        """
        packet_stats = collections.Counter(raw_frame_list)
        # It's not a common frame if it is only seen once.
        packet_stats = {k: v for k, v in packet_stats.items() if v > 1}
        sorted_packets = sorted(
            packet_stats, key=packet_stats.__getitem__, reverse=True)
        counter = 0
        for packet in sorted_packets:
            counter += 1
            if counter == 10:
                break
            packet_text = get_canonical_hex_from_frametext(packet)

            print("Count: {: <7}\n{: <}".format(packet_stats[packet],
                                                packet_text))
        print("To view the content of these packets, subtract the count lines,"
              "\nadd and save to <textfile>, and then run "
              "\n\ntext2pcap <textfile> out.pcap\nwireshark out.pcap\n")

    def intersect_pcap(self):
        """Save pcap intersection. First filename is pivot packet capture.

        generate_intersection also exists as the frame intersect part is
        used by other functions.

        Returns:
            (str): Fileame of generated pcap.
        """
        first_pcap = list(self.pcap_frame_list)[0]
        first_pcap_frames = self.pcap_frame_list[first_pcap]['frames']
        frame_intersection = self.generate_intersection()

        # Print intersection output like in docstring
        intersection_ct = len(frame_intersection)
        print("{: <12} {: <}".format('\nSAME %', 'PCAP NAME'))
        for pcap in self.filenames:
            same_percent = str(
                round(100 * (intersection_ct / len(first_pcap_frames)))) + '%'
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

    def generate_intersection(self):
        """Return the intersection of 2 or more pcaps."""
        pcap_frame_list = dict(self.pcap_frame_list)
        first_pcap = list(pcap_frame_list)[0]
        first_pcap_frames = self.pcap_frame_list[first_pcap]['frames']
        del pcap_frame_list[first_pcap]
        other_pcap_frames = [
            pcap_frame_list[pcap]['frames'] for pcap in pcap_frame_list
            if pcap != first_pcap
        ]
        frame_intersection = set(first_pcap_frames).intersection(
            *other_pcap_frames)
        return frame_intersection

    def difference_pcap(self, pivot_index=0):
        """Given sets A = (1, 2, 3), B = (2, 3, 4), C = (3, 4, 5), A-B-C = (1).

        Args:
            pivot_index [int]: Specify minuend by index of filename in list

        Returns:
            (string): Name of generated pcap.
        """
        minuend_name = list(self.pcap_frame_list)[pivot_index]
        minuend_frame_list = self.pcap_frame_list[minuend_name]['frames']
        other_frame_list = []
        for pcap in self.pcap_frame_list:
            if pcap != minuend_name:
                other_frame_list.extend(self.pcap_frame_list[pcap]['frames'])

        packet_diff = set(minuend_frame_list).difference(set(other_frame_list))

        diff_frame_dict = {}
        for frame in packet_diff:
            # Minuend frame list should have all values we care about.
            diff_frame_dict[frame] = self.frame_timestamp_dict[frame]
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
            (list(str)): Filenames of generated pcaps.
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
            (list(string)): Filenames of generated pcaps.
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

    def inverse_bounded_intersect_pcap(self,
                                       bounded_filelist=False,
                                       intersect_file=False):
        """Inverse of bounded intersection = (bounded intersect) - (intersect)

        Args:
            bounded_filelist (list): List of existing bounded pcaps generated
                by bounded_intersect_pcap()
            intersect_file (string): Location of intersect file.
        Returns:
            (list(string)): Filenames of generated pcaps.
        """
        generated_filelist = []
        has_bounded_intersect_flag = False
        if not bounded_filelist:
            # Don't generate twice if flags -be are used
            # Note that this runs after bounded_intersect if it would be run
            bounded_filelist = self.bounded_intersect_pcap()
            has_bounded_intersect_flag = True
        backup_filenames = self.filenames
        for index, bi_file in enumerate(bounded_filelist):
            self.filenames = [bounded_filelist[index], intersect_file]
            difference_file = self.difference_pcap()
            if difference_file:
                generated_filelist.append(difference_file)
            if has_bounded_intersect_flag:
                # Do not keep bounded-intersect files if they are not necessary
                os.remove(bi_file)
        # Intersect is only used for comparison, so delete it when done.
        self.filenames = backup_filenames
        return generated_filelist

    def get_bounded_pcaps(self):
        """Get the pcap frame list for bounded_intersect_pcap

        Create a bounding box around each packet capture where the bounds are
        the min and max packets in the intersection.

        Returns:
            bounded_pcaps (list): A list of frame_dicts
        """
        min_frame, max_frame = self.get_minmax_common_frames()

        bounded_pcaps = []
        # Each frame_list corresponds to one pcap.
        for pcap in self.pcap_frame_list:
            min_frame_index = -1
            max_frame_index = -1
            frame_list = self.pcap_frame_list[pcap]['frames']
            for frame in self.frame_list:
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
        frame_intersection = self.generate_intersection()

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

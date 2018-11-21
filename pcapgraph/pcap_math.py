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

from pcapgraph.manipulate_framehex import strip_layers, \
    get_frametext_from_files


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
        self.options = options

    def parse_set_args(self, args):
        """Call the appropriate method per CLI flags.

        difference, union, intersect consist of {<op>: {frame: timestamp, ...}}
        bounded_intersect consists of {pcap: {frame: timestamp, ...}, ...}

        Args:
            args (dict): Dict of all arguments (including set args).
        Returns:
            Return generated pcap frames dict with timestamps.
        """
        exclude_empty = args['--exclude-empty']
        generated_pcap_frames = {}
        bounded_intersect_filenames = []
        if args['--difference']:
            diff_filename = 'diff_' + os.path.basename(self.filenames[0])
            generated_pcap_frames[diff_filename] = self.difference_pcap()
        if args['--intersection']:
            generated_pcap_frames['intersect.pcap'] = self.intersect_pcap()
        if args['--symmetric-difference']:
            # Symmetric difference generates multiple files, so extend dict
            generated_pcap_frames = {
                **generated_pcap_frames,
                **self.symmetric_difference_pcap()
            }
        if args['--union']:
            generated_pcap_frames['union.pcap'] = self.union_pcap()
        if args['--bounded-intersection']:
            bounded_intersect_frames = self.bounded_intersect_pcap()
            bounded_intersect_filenames = list(bounded_intersect_frames)
            generated_pcap_frames = {
                **generated_pcap_frames,
                **bounded_intersect_frames
            }
        if args['--inverse-bounded']:
            inv_bounded_pcap_frames = self.inverse_bounded_intersect_pcap(
                generated_pcap_frames,
                bounded_intersect_filenames,
                args['--intersection'],
            )
            generated_pcap_frames = {
                **generated_pcap_frames,
                **inv_bounded_pcap_frames
            }

        for pcap in generated_pcap_frames:
            if generated_pcap_frames[pcap] or not exclude_empty:
                self.pcap_frame_list[pcap] = generated_pcap_frames[pcap]

        return self.pcap_frame_list

    def union_pcap(self):
        """Given sets A = (1, 2, 3), B = (2, 3, 4), A + B = (1, 2, 3, 4).

        About:
            This method uses tshark to get identifying information on
            pcaps and then mergepcap to save the combined pcap.

        Returns:
            (dict): {<FRAME>: <TIMESTAMP>, ...}
        """
        self.print_10_most_common_frames(self.frame_list)

        union_frame_dict = {}
        for index, frame in enumerate(self.frame_list):
            union_frame_dict[frame] = self.timestamp_list[index]
        return union_frame_dict

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
            print("Count: {: <7}\n{: <}".format(packet_stats[packet], packet))
        print("To view the content of these packets, subtract the count lines,"
              "\nadd and save to <textfile>, and then run "
              "\n\ntext2pcap <textfile> out.pcap\nwireshark out.pcap\n")

    def intersect_pcap(self):
        """Save pcap intersection. First filename is pivot packet capture.

        generate_intersection also exists as the frame intersect part is
        used by other functions.

        Returns:
            (dict): Intersection {<FRAME>: <TIMESTAMP>, ...}
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
        arp_ethertype = '0806'
        lacp_ethertype = '8809'
        lldp_ethertype = '88CC'
        nonunique_ethertypes = [arp_ethertype, lldp_ethertype, lacp_ethertype]
        for frame in frame_intersection:
            ethertype = frame[42:44] + frame[45:47]
            # Filter out ARP because they are not unique enough
            if ethertype not in nonunique_ethertypes:
                intersect_frame_dict[frame] = self.frame_timestamp_dict[frame]

        if frame_intersection:
            return intersect_frame_dict
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
            (dict): {<FRAME>: <TIMESTAMP>, ...}
        """
        minuend_name = list(self.pcap_frame_list)[pivot_index]
        minuend_frame_list = self.pcap_frame_list[minuend_name]['frames']
        other_frame_list = []
        for pcap in self.filenames:
            if pcap != minuend_name:
                other_frame_list.extend(self.pcap_frame_list[pcap]['frames'])

        packet_diff = set(minuend_frame_list).difference(set(other_frame_list))

        diff_frame_dict = {}
        for frame in packet_diff:
            # Minuend frame list should have all values we care about.
            diff_frame_dict[frame] = self.frame_timestamp_dict[frame]
        # Save only if there are packets or -x flag is not used.
        if not packet_diff:
            print('WARNING! ' + minuend_name +
                  ' difference contains no packets!')
        return diff_frame_dict

    def symmetric_difference_pcap(self):
        """For sets A = (1, 2, 3), B = (2, 3, 4), C = (3, 4, 5), A△B△C = (1, 5)

        For all pcaps, the symmetric difference produces a pcap that has the
        packets that are unique to only that pcap (unlike above where only one
        set is the result).

        Returns:
            (dict): {<SYMDIFF_PCAP_NAME>: {<FRAME>: <TIMESTAMP>, ...}, ...}
        """
        diff_frame_list = {}
        for index, file in enumerate(self.filenames):
            diff_frames = self.difference_pcap(pivot_index=index)
            basename = os.path.splitext(os.path.basename(file))[0]
            symdiff_filename = 'symdiff_' + basename + '.pcap'
            diff_frame_list[symdiff_filename] = diff_frames

        return diff_frame_list

    def inverse_bounded_intersect_pcap(self, new_pcap_frames,
                                       bounded_filenames, has_intersection):
        """Inverse of bounded intersection = (bounded intersect) - (intersect)

        Args:
            new_pcap_frames (dict): All frames and timestamps created
                by other operations thus far.
            bounded_filenames (list): Filenames of bounded intersections
            has_intersection (bool): Whether an intersection has been done
        Returns:
            (dict): Filenames of generated pcaps.
        """
        inv_bounded_frame_dict = {}
        # Don't generate same dicts twice
        if bounded_filenames:
            bounded_frame_dict = {}
            for file in bounded_filenames:
                bounded_frame_dict[file] = dict(new_pcap_frames[file])
        else:
            bounded_frame_dict = self.bounded_intersect_pcap()
        if has_intersection:
            intersect_frame_dict = new_pcap_frames['intersect.pcap']
        else:
            intersect_frame_dict = self.intersect_pcap()
        intersect_set = set(intersect_frame_dict)
        for file in bounded_frame_dict:
            inv_bounded_frame_dict['inv_' + file] = \
                set(bounded_frame_dict[file]).difference(intersect_set)

        return inv_bounded_frame_dict

    def bounded_intersect_pcap(self):
        """Get the pcap frame list for bounded_intersect_pcap

        Create a bounding box around each packet capture where the bounds are
        the min and max packets in the intersection.

        Returns:
            (dict): {<BOUNDED_PCAP_NAME>: {<FRAME>: <TIMESTAMP>, ...}, ...}

        """
        min_frame, max_frame = self.get_minmax_common_frames()

        bounded_pcaps = {}
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
            basename = os.path.splitext(os.path.basename(pcap))[0]
            bounded_filename = 'bounded_intersect-' + basename + '.pcap'
            bounded_pcaps[bounded_filename] = bounded_pcap_with_timestamps

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

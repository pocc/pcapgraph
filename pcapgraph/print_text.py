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
"""Print text instead of a graph."""
import datetime


def output_text(pcap_times):
    """Make useful text given pcap times.

    Args:
        pcap_times (dict): Packet capture names and start/stop timestamps.
    Returns:
        (str): Full textstring of text to written to file/stdout
    """

    result_string = '\nPCAP NAME           YEAR  DATE 0  DATE $' \
                    '     TIME 0    TIME $       UTC 0' + 14*' ' + 'UTC $'
    for pcap in sorted(pcap_times.keys()):
        pcap_year = datetime.datetime.fromtimestamp(
            pcap_times[pcap]['pcap_start']).strftime('%Y')
        pcap_pretty_startdate = datetime.datetime.fromtimestamp(
            pcap_times[pcap]['pcap_start']).strftime('%b-%d')
        pcap_pretty_enddate = datetime.datetime.fromtimestamp(
            pcap_times[pcap]['pcap_end']).strftime('%b-%d')
        pcap_pretty_starttime = datetime.datetime.fromtimestamp(
            pcap_times[pcap]['pcap_start']).strftime('%H:%M:%S')
        pcap_pretty_endtime = datetime.datetime.fromtimestamp(
            pcap_times[pcap]['pcap_end']).strftime('%H:%M:%S')
        pcap_name_string = pcap[:17]  # Truncate if too long

        # Formatter creates a bunch of columns aligned left with num spacing.
        format_string = "\n{: <19} {: <5} {: <7} " \
                        "{: <10} {: <9} {: <12} {: <18} {: <18}"
        result_string += format_string.format(
            pcap_name_string,
            pcap_year,
            pcap_pretty_startdate,
            pcap_pretty_enddate,
            pcap_pretty_starttime,
            pcap_pretty_endtime,
            pcap_times[pcap]['pcap_start'],
            pcap_times[pcap]['pcap_end'],
        )

    return result_string

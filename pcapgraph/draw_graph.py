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
"""Draw graph will draw a text or image graph."""

import datetime
import os

import matplotlib.pyplot as plt
import numpy as np


def draw_graph(pcap_times, save_fmt):
    """Draw a graph using matplotlib and numpy.

    Args:
        pcap_times (dict):
        save_fmt (str): The save file type. Supported formats are dependent
            on the capabilites of the system: [png, pdf, ps, eps, and svg]. See
            https://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.savefig
            for more information.
    """
    if save_fmt == 'txt':
        output_text = make_text_not_war(pcap_times)
        print(output_text)
        with open('pcap_graph.txt', 'w') as file:
            file.write(output_text)
            file.close()
        print("Text file successfully created!")
    else:
        start_times, end_times, pcap_names = setup_graph_vars(pcap_times)

        generate_graph(pcap_names, start_times, end_times)
        export_graph(pcap_times, pcap_names, save_fmt)


def setup_graph_vars(pcap_times):
    """Setup graph variables

    Args:
        pcap_times (dict): Packet capture names and start/stop timestamps.
    """
    start_times = []
    end_times = []
    pcap_names = []
    # Sorted by first timestamp so that graph looks like a staircase.
    sorted_pcap_names = sorted(pcap_times,
                               key=lambda x: pcap_times[x]['pcap_starttime'])
    for pcap in sorted_pcap_names:
        start_times.append(pcap_times[pcap]['pcap_starttime'])
        end_times.append(pcap_times[pcap]['pcap_endtime'])
        similarity = ''
        similarity_percent = pcap_times[pcap]['pivot_similarity']
        if similarity_percent:
            similarity = ' (' + str(similarity_percent) + '%)'
        pcap_names.append(pcap + similarity)  # Add percentage if it exists

    start_times_array = np.array(start_times)
    end_times_array = np.array(end_times)

    return start_times_array, end_times_array, pcap_names


def generate_graph(pcap_names, start_times, end_times):
    """Generate the matplotlib graph.

    Args:
        pcap_names
    """
    # first and last are the first and last timestamp of all pcaps.
    first_time = min(start_times)
    last_time = max(end_times)
    # Force padding on left and right sides
    graph_one_percent_width = (last_time - first_time) / 100
    first = first_time - graph_one_percent_width
    last = last_time + graph_one_percent_width

    fig, axes = plt.subplots()
    barlist = plt.barh(
        range(len(start_times)), end_times - start_times, left=start_times)

    set_horiz_bar_colors(barlist)
    # xticks will look like 'Dec-31   23:59:59'
    x_ticks = set_xticks(first, last)
    #    plt.tight_layout(
    # Print all x labels that aren't at the lower corners
    plt.xticks(rotation=45)
    axes.set_xticks(np.round(np.linspace(first, last, 10)))
    axes.set_xticklabels(x_ticks)
    for tick in axes.xaxis.get_majorticklabels():
        tick.set_horizontalalignment("right")
    # Pcap names as y ticks. Position them halfway up the bar.
    plt.yticks(np.arange(len(pcap_names), step=1), pcap_names)
    axes.set_xlabel('Time', fontsize=16)
    axes.set_ylabel('Pcap Name', fontsize=16)
    fig.suptitle('Pcap Time Analysis', fontsize=20)
    # Use 0.95 for top because tight_layout does not consider suptitle
    plt.tight_layout(rect=[0, 0, 1, 0.95])


def set_horiz_bar_colors(barlist):
    """Set the horizontal bar colors.

    Color theme is Metro UI, with an emphasis on darker colors. If there are
    more horiz bars than in the color array, loop and continue to set colors.

    Args:
        barlist
    """
    colors = [
        '#2d89ef', '#603cba', '#2b5797', '#b91d47', '#99b433', '#da532c',
        '#00a300', '#7e3878', '#00aba9', '#1e7145', '#9f00a7', '#e3a21a'
    ]
    color_count = len(colors)
    for i, hbar in enumerate(barlist):
        color = colors[i % color_count]
        hbar.set_color(color)


def set_xticks(first, last):
    """Generate the x ticks and return a list of them.

    Args:
        first:
    Returns:
        ()
    """
    # 10 x ticks chosen for aesthetic reasons.
    xticks_qty = 10
    x_ticks = xticks_qty * ['']
    offset = first
    step = (last - first) / (xticks_qty - 1)
    for i in range(xticks_qty):
        x_ticks[i] = datetime.datetime.fromtimestamp(offset).strftime(
            '%b-%d   %H:%M:%S')
        offset += step

    return x_ticks


def export_graph(pcap_times, pcap_names, save_fmt):
    """Exports the graph to the screen or to a file."""
    if save_fmt:
        this_folder = os.getcwd()
        pivot_file = pcap_names[0].split(' ')[0] + '.'
        plt.savefig(
            this_folder + '\\pcap_graph-' + pivot_file + save_fmt,
            format=save_fmt,
            transparent=True)
        print(save_fmt, "file successfully created!")
    else:
        # Print text version because it's possible.
        print(make_text_not_war(pcap_times))
        plt.show()


def make_text_not_war(pcap_times):
    """Make useful text given pcap times.

    Args:
        pcap_times (dict): Packet capture names and start/stop timestamps.
    Returns:
        (string): Full textstring of text to written to file/stdout
    """
    result_string = 'PCAP NAME           DATE 0  DATE $     TIME 0    ' \
                    'TIME $       UTC 0' + 14*' ' + 'UTC $'
    for pcap in sorted(pcap_times.keys()):
        pcap_pretty_startdate = datetime.datetime.fromtimestamp(
            pcap_times[pcap]['pcap_starttime']).strftime('%b-%d')
        pcap_pretty_enddate = datetime.datetime.fromtimestamp(
            pcap_times[pcap]['pcap_endtime']).strftime('%b-%d')
        pcap_pretty_starttime = datetime.datetime.fromtimestamp(
            pcap_times[pcap]['pcap_starttime']).strftime('%H:%M:%S')
        pcap_pretty_endtime = datetime.datetime.fromtimestamp(
            pcap_times[pcap]['pcap_endtime']).strftime('%H:%M:%S')
        if pcap_times[pcap]['pivot_similarity']:
            pcap_name_string = '(' + "{: >3}".format(
                str(pcap_times[pcap]['pivot_similarity'])) + '%) ' + pcap[:11]
        else:
            pcap_name_string = pcap[:17]  # Truncate if too long

        # Formatter creates a bunch of columns aligned left with num spacing.
        format_string = "\n{: <19} {: <7} " \
                        "{: <10} {: <9} {: <12} {: <18} {: <18}"
        result_string += format_string.format(
            pcap_name_string,
            pcap_pretty_startdate,
            pcap_pretty_enddate,
            pcap_pretty_starttime,
            pcap_pretty_endtime,
            pcap_times[pcap]['pcap_starttime'],
            pcap_times[pcap]['pcap_endtime'],
        )

    return result_string

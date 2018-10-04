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
        start_times, end_times, pcap_names = get_graph_vars(pcap_times)

        generate_graph(pcap_names, start_times, end_times)
        export_graph(pcap_times, pcap_names, save_fmt)


def get_graph_vars(pcap_times):
    """Setup graph variables.

    This function exists to decrease the complexity of generate graph.
    The order of return vars start_times_array, end_times_array, and pcap_names
    should all match. In other words, the start_times_array[5] is for the
    same pcap as end_times_array[5] and pcap_names[5].

    Args:
        pcap_times (dict): Packet capture names and start/stop timestamps.
    Returns:
        start_times_array (list): List of all end times of pcaps.
        end_times_array (list): List of all start times of pcaps.
        pcap_names (list): List of pcap names.
    """
    start_times = []
    end_times = []
    pcap_names = []
    # Sorted by first timestamp so that graph looks like a staircase.
    sorted_pcap_names = sorted(
        pcap_times)
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
        pcap_names (list(str)): List of pcap file names.
        start_times (list(float)): List of start times of all pcaps.
        end_times (list(float)): List of end times of all pcaps.
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
    x_ticks, xlabel = set_xticks(first, last)
    # Print all x labels that aren't at the lower corners
    plt.xticks(rotation=45)
    axes.set_xticks(np.round(np.linspace(first, last, 10)))
    axes.tick_params(axis='y', labelsize=12)     # Set ytick fontsize to 10
    axes.set_xticklabels(x_ticks)
    for tick in axes.xaxis.get_majorticklabels():
        tick.set_horizontalalignment("right")
    # Each line has text that is 12 point high; 72 point = 1 inch, so for each
    # additional pcap, add 1/6 inch. Default graph is 3 in high, so y tick text
    # should start overlapping at 18 lines.
    # If number of pcaps is greater than 18, remove the names
    if len(pcap_names) > 18:
        pcap_names = len(pcap_names) * ['']
    #adjusted_height = (len(pcap_names) - 18) * 2
    #fig.set_figheight(5.5 + adjusted_height)
    # If there's more than 18 packet captures, don't show the names.
    #pcap_names = len(pcap_names) * ['']
    # Pcap names as y ticks. Position them halfway up the bar.
    plt.yticks(np.arange(len(pcap_names), step=1), pcap_names)
    axes.set_ylim(-0.5, len(pcap_names) - 0.5)
    # xlabel will be 'Time' if different years, and 'Time (YYYY)' if same year.
    axes.set_xlabel(xlabel, fontsize=16)
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
        '#2d89ef', '#603cba', '#2b5797', '#7e3878', '#b91d47', '#9f00a7',
        '#00a300', '#da532c', '#00aba9', '#1e7145', '#99b433', '#e3a21a'
    ]
    color_count = len(colors)
    for i, hbar in enumerate(barlist):
        color = colors[i % color_count]
        hbar.set_color(color)


def set_xticks(first, last):
    """Generate the x ticks and return a list of them.

    Args:
        first: Earliest timestamp of pcaps.
        last: Latest timestamp of pcaps.
    Returns:
        x_ticks (list(float)): List of unix epoch time values as xticks.
        x_label (string): Text to be used to label X-axis.
    """
    # 10 x ticks chosen for aesthetic reasons.
    xticks_qty = 10
    x_ticks = xticks_qty * ['']
    offset = first
    step = (last - first) / (xticks_qty - 1)
    # If first and last timestamps are in different years, add year to xtick
    # xlabel will be 'Time' if different years, and 'Time (YYYY)' if same year.
    strftime_string = '%b-%d   %H:%M:%S'
    first_time_year = datetime.datetime.fromtimestamp(first).strftime('%Y')
    last_time_year = datetime.datetime.fromtimestamp(last).strftime('%Y')
    if first_time_year != last_time_year:
        strftime_string = '%Y-' + '%b-%d   %H:%M:%S'
        xlabel = 'Time'
    else:
        xlabel = 'Time (' + first_time_year + ')'
    for i in range(xticks_qty):
        x_ticks[i] = datetime.datetime.fromtimestamp(offset).strftime(
            strftime_string)
        offset += step

    return x_ticks, xlabel


def export_graph(pcap_times, pcap_names, save_fmt):
    """Exports the graph to the screen or to a file."""
    if save_fmt:
        this_folder = os.getcwd()
        pivot_file = pcap_names[0].split(' ')[0] + '.'
        plt.savefig(
            'pcap_graph-' + pivot_file + save_fmt,
            format=save_fmt,
            transparent=True)
        print(save_fmt, "file successfully created in ", this_folder, "!")
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
    result_string = 'PCAP NAME           YEAR  DATE 0  DATE $' \
                    '     TIME 0    TIME $       UTC 0' + 14*' ' + 'UTC $'
    for pcap in sorted(pcap_times.keys()):
        pcap_year = datetime.datetime.fromtimestamp(pcap_times[pcap][
            'pcap_starttime']).strftime('%Y')
        pcap_pretty_startdate = datetime.datetime.fromtimestamp(pcap_times[
            pcap]['pcap_starttime']).strftime('%b-%d')
        pcap_pretty_enddate = datetime.datetime.fromtimestamp(pcap_times[pcap][
            'pcap_endtime']).strftime('%b-%d')
        pcap_pretty_starttime = datetime.datetime.fromtimestamp(pcap_times[
            pcap]['pcap_starttime']).strftime('%H:%M:%S')
        pcap_pretty_endtime = datetime.datetime.fromtimestamp(pcap_times[pcap][
            'pcap_endtime']).strftime('%H:%M:%S')
        if pcap_times[pcap]['pivot_similarity']:
            pcap_name_string = '(' + "{: >3}".format(
                str(pcap_times[pcap]['pivot_similarity'])) + '%) ' + pcap[:11]
        else:
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
            pcap_times[pcap]['pcap_starttime'],
            pcap_times[pcap]['pcap_endtime'], )

    return result_string

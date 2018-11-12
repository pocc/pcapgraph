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
import subprocess as sp

import matplotlib.pyplot as plt
import numpy as np

import pcapgraph.manipulate_frames as mf


def draw_graph(pcap_packets, input_files, output_fmts, exclude_empty,
               anonymize_names):
    """Draw a graph using matplotlib and numpy.

    Args:
        pcap_packets (dict): All packets, where key is pcap filename/operation.
        input_files (list): List of input files that shouldn't be deleted.
        output_fmts (list): The save file type. Supported formats are dependent
            on the capabilites of the system: [png, pdf, ps, eps, and svg]. See
            https://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.savefig
            for more information.
        exclude_empty (bool): Whether to exclude empty pcaps from graph.
        anonymize_names (bool): Whether to change filenames to random values.
    """
    # So that if no save format is specified, print to screen and stdout
    if not output_fmts:
        output_fmts = ['show']
    pcap_filenames = list(pcap_packets)
    delete_pcaps = True
    open_in_wireshark = False
    if 'wireshark' in output_fmts:
        output_fmts.remove('wireshark')
        open_in_wireshark = True
    if 'pcap' in output_fmts:
        output_fmts.remove('pcap')
        delete_pcaps = False
    if 'pcapng' in output_fmts:
        output_fmts.remove('pcapng')
        delete_pcaps = False
    for save_format in output_fmts:
        output_file(save_format, pcap_packets, exclude_empty, anonymize_names)

    new_files = set(pcap_filenames) - set(input_files)
    remove_or_open_files(new_files, open_in_wireshark, delete_pcaps)


def output_file(save_format, pcap_packets, exclude_empty, anonymize_names):
    """Save the specified file with the specified format.

    Args:
        save_format (str): Extension of file to be saved.
        pcap_packets (dict): All packets, where key is pcap filename/operation.
        exclude_empty (bool): Whether to exclude empty pcaps from graph.
        anonymize_names (bool): Whether to change filenames to random values.
    """
    pcap_filenames = list(pcap_packets)
    if save_format == 'txt':
        output_text = make_text_not_war(pcap_packets)
        print(output_text)
        with open('pcap_graph.txt', 'w') as file:
            file.write(output_text)
            file.close()
        print("Text file successfully created!")
    else:
        graph_startstop_dict = mf.get_pcap_info(pcap_filenames)
        empty_files = []
        if not exclude_empty:
            for pcap in pcap_packets:
                if not pcap_packets[pcap]['frames']:
                    pcap_name = os.path.basename(os.path.splitext(pcap)[0])
                    empty_files += [pcap_name]
        generate_graph(graph_startstop_dict, empty_files, anonymize_names)
        if save_format != 'show':
            export_graph(pcap_filenames, save_format)
        else:
            # Print text version because it's possible.
            print(make_text_not_war(graph_startstop_dict))
            plt.show()


def remove_or_open_files(new_files, open_in_wireshark, delete_pcaps):
    """Remove or open files.

    delete_pcaps and open_in_wireshark should not both be true, because that
    would mean that wireshark would try to open deleted files.

    Args:
        new_files (set): Set of new filenames to do something with
        open_in_wireshark (bool): Whether to open files in wireshark
        delete_pcaps (bool): Whether to delete generated pcaps
    """
    # Open all created files in wireshark (flag -w)
    if open_in_wireshark:
        for file in new_files:
            print("Opening", file, "in wireshark.")
            sp.Popen(['wireshark', file])

    if delete_pcaps:
        # Delete temp files if not required.
        for file in new_files:
            os.remove(file)


def generate_graph(pcap_vars, empty_files, anonymize_names):
    """Generate the matplotlib graph.

    Args:
        pcap_vars (dict): Contains all data required for the graph.
            {<pcap>: {'pcap_start': <timestamp>, 'pcap_end': <timestamp>}, ...}
        empty_files (list): List of filenames of empty files.
        anonymize_names (bool): Whether to use pseudorandom names for files.
    """
    # first and last are the first and last timestamp of all pcaps.
    pcap_names = list(pcap_vars) + empty_files
    if anonymize_names:
        pcap_names = mf.anonymous_pcap_names(len(pcap_names))
    start_times = np.array(
        [pcap_vars[pcap]['pcap_start'] for pcap in pcap_vars])
    end_times = np.array([pcap_vars[pcap]['pcap_end'] for pcap in pcap_vars])
    x_min, x_max = get_x_minmax(start_times, end_times)

    fig, axes = plt.subplots()
    barlist = plt.barh(
        range(len(start_times)), end_times - start_times, left=start_times)

    set_horiz_bar_colors(barlist)
    # xticks will look like 'Dec-31   23:59:59'
    x_ticks, xlabel = set_xticks(x_min, x_max)
    # Print all x labels that aren't at the lower corners
    plt.xticks(rotation=45)
    axes.set_xticks(np.round(np.linspace(x_min, x_max, 10)))
    axes.tick_params(axis='y', labelsize=12)  # Set ytick fontsize to 10
    axes.set_xticklabels(x_ticks)
    for tick in axes.xaxis.get_majorticklabels():
        tick.set_horizontalalignment("right")
    # Each line has text that is 12 point high; 72 point = 1 inch, so for each
    # additional pcap, add 1/6 inch. Default graph is 3 in high, so y tick text
    # should start overlapping at 18 lines.
    # If number of pcaps is greater than 18, remove the names
    if len(pcap_names) > 18:
        pcap_names = len(pcap_names) * ['']
    # adjusted_height = (len(pcap_names) - 18) * 2
    # fig.set_figheight(5.5 + adjusted_height)
    # If there's more than 18 packet captures, don't show the names.

    # Pcap names as y ticks. Position them halfway up the bar.
    plt.yticks(np.arange(len(pcap_names), step=1), pcap_names)
    axes.set_ylim(-0.5, len(pcap_names) - 0.5)
    # xlabel will be 'Time' if different years, and 'Time (YYYY)' if same year.
    axes.set_xlabel(xlabel, fontsize=16)
    axes.set_ylabel('Pcap Name', fontsize=16)
    fig.suptitle('Pcap Time Analysis', fontsize=20)
    # Use 0.95 for top because tight_layout does not consider suptitle
    plt.tight_layout(rect=[0, 0, 1, 0.95])


def get_x_minmax(start_times, end_times):
    """Determine the horizontal (x) min and max values.

    This function adds 1% to either side for padding.

    Args:
        start_times (np.array): First packet unix timestamps of all pcaps.
        end_times (np.array): Last packet unix timestamps of all pcaps.
    Returns:
        (tuple): min_x, max_x to be used for graph
    """
    first_time = min(start_times)
    last_time = max(end_times)
    # Force padding on left and right sides
    graph_one_percent_width = (last_time - first_time) / 100
    first = first_time - graph_one_percent_width
    last = last_time + graph_one_percent_width

    return first, last


def set_horiz_bar_colors(barlist):
    """Set the horizontal bar colors.

    Color theme is Metro UI, with an emphasis on darker colors. If there are
    more horiz bars than in the color array, loop and continue to set colors.

    Args:
        barlist (list): List of the horizontal bars.
    """
    colors = [
        '#2d89ef',
        '#603cba',
        '#2b5797',
        '#008B8B',
        '#3145b4',
        '#36648B',
        '#38b0de',
        '#4d4dff',
        '#3299cc',
        '#7f00ff',
        '#03b4c8',
        '#5959ab',
    ]
    color_count = len(colors)
    for i, hbar in enumerate(barlist):
        color = colors[i % color_count]
        hbar.set_color(color)


def set_xticks(first, last):
    """Generate the x ticks and return a list of them.

    Args:
        first (float): Earliest timestamp of pcaps.
        last (float): Latest timestamp of pcaps.
    Returns:
        (tuple):
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


def export_graph(pcap_names, save_fmt):
    """Exports the graph to the screen or to a file.

    Args:
        pcap_names (list): List of pcap_names
        save_fmt (str): File extension of output file
    """
    this_folder = os.getcwd()
    pcap_name = pcap_names[-1].split('.pcap')[0]
    last_operation_file = pcap_name.split(' ')[0] + '.'
    plt.savefig(
        'pcap_graph-' + last_operation_file + save_fmt,
        format=save_fmt,
        transparent=True)
    print(save_fmt, "file successfully created in ", this_folder, "!")


def make_text_not_war(pcap_times):
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

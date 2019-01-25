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
import random

import matplotlib.pyplot as plt
import numpy as np


def show_graph():
    """Show graph."""
    plt.show()


def generate_graph(pcap_packets, pcap_vars, empty_files, anonymize_names,
                   show_packets):
    """Generate the matplotlib graph.

    Args:
        pcap_packets (dict): Dict returned by get_pcap_frame_dict()
            {<pcap>: {'FRAME': 'TIMESTAMP', ...}, ...}
        pcap_vars (dict): Contains all data required for the graph.
            {<pcap>: {'pcap_start': <timestamp>, 'pcap_end': <timestamp>}, ...}
        empty_files (list): List of filenames of empty files.
        anonymize_names (bool): Whether to change filenames to random values.
        show_packets (bool): Whether to show each packet or the entire pcap.
    """
    # first and last are the first and last timestamp of all pcaps.
    pcap_names = list(pcap_vars)
    if anonymize_names:
        pcap_names = anonymous_pcap_names(len(pcap_names))
    # Each line has text that is 12 point high; 72 point = 1 inch, so for each
    # additional pcap, add 1/6 inch. Default graph is 3 in high, so y tick text
    # should start overlapping at 18 lines.
    # If number of pcaps is greater than 18, remove the names
    # adjusted_height = (len(pcap_names) - 18) * 2
    # fig.set_figheight(5.5 + adjusted_height)
    if len(pcap_names) > 18:
        pcap_names = len(pcap_names) * ['']
    start_times = np.array(
        [pcap_vars[pcap]['pcap_start'] for pcap in pcap_vars])
    end_times = np.array([pcap_vars[pcap]['pcap_end'] for pcap in pcap_vars])
    pcap_names += empty_files
    x_min, x_max = get_x_minmax(start_times, end_times)

    fig, axes = plt.subplots()
    if show_packets:
        print("Loading packets as lines...")
        plt.xlim(x_min, x_max)
        set_horiz_barlines(pcap_packets)
        print("Done loading packets!")
    else:  # Default is to show horizontal bars for bar graph
        barlist = plt.barh(
            range(len(start_times)), end_times - start_times, left=start_times)
        set_horiz_bars(barlist)

    set_graph_vars(x_min, x_max, pcap_names, fig, axes)


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


def set_horiz_bars(barlist):
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


def set_horiz_barlines(pcap_packets):
    """Set horizontal bar vertical lines instead of a fully-colored bar."""
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

    hbar_height = 1 / len(pcap_packets)
    for index, pcap in enumerate(pcap_packets):
        # Create a line in a bar graph with 10% pad on each side
        ymin = index * hbar_height + .1 * hbar_height
        ymax = ymin + hbar_height - .2 * hbar_height
        for packet in pcap_packets[pcap]:
            timestamp = float(pcap_packets[pcap][packet])
            plt.axvline(
                x=timestamp,
                ymin=ymin,
                ymax=ymax,
                color=colors[index],
                linewidth='1')


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


def set_graph_vars(x_min, x_max, pcap_names, fig, axes):
    """Set matplotlib's plt object with appropriate graph parameters."""
    # xticks will look like 'Dec-31   23:59:59'
    x_ticks, xlabel = set_xticks(x_min, x_max)
    # Print all x labels that aren't at the lower corners
    plt.xticks(rotation=45)
    axes.set_xticks(np.round(np.linspace(x_min, x_max, 10)))
    axes.tick_params(axis='y', labelsize=12)  # Set ytick fontsize to 10
    axes.set_xticklabels(x_ticks)
    for tick in axes.xaxis.get_majorticklabels():
        tick.set_horizontalalignment("right")

    # Pcap names as y ticks. Position them halfway up the bar.
    plt.yticks(np.arange(len(pcap_names), step=1), pcap_names)
    axes.set_ylim(-0.5, len(pcap_names) - 0.5)
    # xlabel will be 'Time' if different years, and 'Time (YYYY)' if same year.
    axes.set_xlabel(xlabel, fontsize=16)
    axes.set_ylabel('Pcap Name', fontsize=16)
    fig.suptitle('Pcap Time Analysis', fontsize=20)
    # Use 0.95 for top because tight_layout does not consider suptitle
    plt.tight_layout(rect=[0, 0, 1, 0.95])


def export_graph(pcap_names, save_fmt):
    """Exports the graph to the screen or to a file.

    Args:
        pcap_names (list): List of pcap_names
        save_fmt (str): File extension of output file
    """
    this_folder = os.getcwd()
    last_operation = os.path.basename(pcap_names[-1]).split('.pcap')[0]
    last_operation_file = last_operation.split(' ')[0] + '.'
    plt.savefig(
        'pcap_graph-' + last_operation_file + save_fmt,
        format=save_fmt,
        transparent=True)
    print(save_fmt, "file successfully created in ", this_folder, "!")


def anonymous_pcap_names(num_names):
    """Anonymize pcap names.

    Graph feature that does not require matplotlib (i.e. is separable).
    Creation of funny pcap names like `switch_wireless` is intendeded behavior.

    Args:
        num_names (int): Number of names to be returned
    Returns:
        (list): Fake pcap name list
    """
    fake_city_names = [
        'Hogwarts', 'Quahog', 'Lake Wobegon', 'Narnia', 'Ankh Morpork',
        'Gotham City', 'Asgard', 'Neverland', 'The Shire', 'Rivendell',
        'Diagon Alley', 'King\'s Landing', 'Cooper Station', 'Dragonstone',
        'El Dorado', 'Atlantis', 'Pallet Town', 'Shangri-La', 'Mos Eisley'
    ]
    fake_device_names = [
        'firewall', 'router', 'access point', 'switch', 'bridge', 'repeater',
        'dial-up modem', 'proxy server', 'hub', 'tokenring mau', 'gateway',
        'turbo encabulator', 'L3 switch', 'HIDS', 'load balancer',
        'packet shaper', 'vpn concentrator', 'content filter', 'CSU/DSU'
    ]
    fake_names = []

    for _ in range(num_names):
        fake_place = random.choice(fake_city_names)
        fake_device = random.choice(fake_device_names)
        fake_name = fake_place + '-' + fake_device
        fake_names.append(fake_name)

    return fake_names


def get_matplotlib_fmts():
    """Get the matplotlib supported formats.

    Supported save file types will vary across platforms.
    """
    supported_format_list = set(plt.gcf().canvas.get_supported_filetypes())
    return supported_format_list

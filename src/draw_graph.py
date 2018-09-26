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

import datetime

import matplotlib.pyplot as plt
import numpy as np


def draw_graph(pcap_times, save_fmt, output_fmt):
    """Draw a graph using matplotlib and numpy.

    Args:
        pcap_times (dict):
        save_fmt (str): The save file type. Supported formats are dependent
            on the capabilites of the system: [png, pdf, ps, eps, and svg]. See
            https://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.savefig
            for more information.
        output_fmt (bool): (1) print to the screen/stdout (0) print to a file
    """
    if save_fmt == 'txt':
        output_text = make_text_not_war(pcap_times)
        if output_fmt:
            print(output_text)
        else:
            with open('pcap_graph.txt', 'w') as file:
                file.write(output_text)
                file.close()
            print("Text file successfully created!")
    else:
        start_times = []
        end_times = []
        pcap_names = []
        for pcap in sorted(pcap_times.keys()):
            start_times.append(pcap_times[pcap]['pcap_starttime'])
            end_times.append(pcap_times[pcap]['pcap_endtime'])
            similarity = ''
            similarity_percent = pcap_times[pcap]['pivot_similarity']
            if similarity_percent:
                similarity = ' (' + str(similarity_percent) + '%)'
            pcap_names.append(pcap + similarity)  # Add percentage if it exists

        fig, ax = plt.subplots()

        begin = np.array(start_times)
        end = np.array(end_times)
        first = min(start_times)
        last = max(end_times)

        plt.barh(range(len(begin)),  end-begin, left=begin)

        step = (last - first) / 9
        x_ticks = [first]
        for i in range(9):
            x_ticks.append(x_ticks[i] + step)

        # xticks will look like 'Dec-31   23:59:59'
        for i in range(10):
            x_ticks[i] = datetime.datetime.fromtimestamp(
                x_ticks[i]).strftime('%b-%d   %H:%M:%S')

        # Print all x labels that aren't at the lower corners
        plt.xticks(rotation=45)
        ax.set_xticks(np.round(np.linspace(first, last, 10)))
        ax.set_xticklabels(x_ticks)
        for tick in ax.xaxis.get_majorticklabels():
            tick.set_horizontalalignment("right")
        # Pcap names as y ticks. Position them halfway up the bar.
        plt.yticks(np.arange(0.5, len(pcap_names), step=1), pcap_names)
        ax.set_xlabel('Time', fontsize=16)
        ax.set_ylabel('Pcap Name', fontsize=16)
        fig.suptitle('Pcap Time Analysis', fontsize=20)
        # Use 0.95 for top because tight_layout does not consider suptitle
        plt.tight_layout(rect=[0, 0, 1, 0.95])
        if save_fmt:
            plt.savefig('pcap_graph.' + save_fmt, format=save_fmt)
            print(save_fmt, "file successfully created!")
        else:
            plt.show()


def make_text_not_war(pcap_times):
    """Make text given pcap times."""
    result_string = 'PCAP NAME            DATE 0  DATE $    TIME 0    ' \
                    'TIME $      UTC 0' + 14*' ' + 'UTC $'
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
            pcap_name_string = pcap[:18]  # Truncate if too long

        # Formatter creates a bunch of columns aligned left with num spacing.
        format_string = "\n{: <20} {: <7} " \
                        "{: <9} {: <9} {: <11} {: <18} {: <18}"
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

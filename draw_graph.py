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


def draw_graph(pcap_times):
    """Draw a graph using matplotlib and numpy."""
    start_times = []
    end_times = []
    for pcap in sorted(pcap_times.keys()):
        start_times.append(pcap_times[pcap]['pcap_starttime'])
        end_times.append(pcap_times[pcap]['pcap_endtime'])

    print(start_times)
    print(end_times)

    fig, ax = plt.subplots()

    begin = np.array(start_times)
    end = np.array(end_times)
    first = min(start_times)
    last = max(end_times)

    plt.barh(range(len(begin)),  end-begin, left=begin)

    step = (last - first) / 10
    x_ticks = [first]
    for i in range(9):
        x_ticks.append(x_ticks[i] + step)

    # xticks will look like 'Dec-31 23:59:59'
    for i in range(10):
        x_ticks[i] = datetime.datetime.fromtimestamp(x_ticks[i]).strftime(
            '%b-%d   %H:%M:%S')
        print(x_ticks[i])

    # Print all x labels that aren't at the lower-left or lower-right corner.
    ax.set_xticklabels(x_ticks[1:])
    ax.set_xticks(np.round(np.linspace(first, last, 10), 2))
    plt.xticks(rotation=45)
    pcap_names = pcap_times.keys()
    # Pcap names as y ticks. Position them halfway up the bar.
    plt.yticks(np.arange(0.4, len(pcap_names), step=1),
               sorted(pcap_names, reverse=True))
    ax.set_xlabel('Time', fontsize=16)
    ax.set_ylabel('Pcap Name', fontsize=16)
    fig.suptitle('Pcap Time Analysis', fontsize=20)
    # Use 0.95 for top because tight_layout does not consider suptitle
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.show()

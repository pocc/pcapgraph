# -*- coding: utf-8 -*-

import json

import matplotlib.pyplot as plt
import numpy as np
import datetime

with open('sample.json') as json_data:
    pcap_times = json.load(json_data)
    json_data.close()
start_times = []
end_times = []
for pcap in sorted(pcap_times.keys()):
    start_times.append(pcap_times[pcap]['epoch_start'])
    end_times.append(pcap_times[pcap]['epoch_end'])

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

for i in range(10):
    x_ticks[i] = datetime.datetime.fromtimestamp(x_ticks[i]).strftime(
        '%b-%d   %H:%M:%S')
    print(x_ticks[i])
ax.set_xticklabels(x_ticks)
ax.set_xticks(np.round(np.linspace(first, last, 10), 2))
plt.xticks(rotation=90)
plt.yticks(range(len(begin)), sorted(pcap_times.keys(), reverse=True))
plt.tight_layout()
plt.show()

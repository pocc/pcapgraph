# PcapGraph
*This requires features from **python3.6**. It would be prudent to use this 
version of python or later.*

PcapGraph takes packet captures and creates a bar graph out of the start/end
timestamps. If the --compare option is used, packet captures are compared 
packet by packet to find what percentage of traffic is the same. A list of 
files, directories, and any combination thereof can be specified.
## Use case
### Scenario
* You have a bunch of packet captures all from multiple interfaces on a 
network
* You need to verify that they were taken at the same time and contain the 
same packets 
 
### Solution
Use pcapgraph to visually see where there is time and traffic overlap.

## Installation
### Steps
##### 1. Install Wireshark
* These package managers have it in their repositories:
`apt`, `dnf`, `pacman`, `brew`, `choco`, `...`
* You can also download precompiled binaries [here](https://www.wireshark.org/download.html)

##### 2. Install pcapgraph with pip
    pip install --user pcapgraph

### Installation Errors
*These are some of the errors I came across during testing. If you find 
more, please let me know.*
#### _tkinter not installed
* On ubuntu, you may need to install the `python3.6-tk` package to 
use the tkinter parts of matplotlib.

#### ImportError: cannot import name 'multiarray'
If you have versions of numpy or matplotlib that were installed with a 
non-3.6 version of python, you may need to reinstall both.

    python3.6 -m pip uninstall -y numpy matplotlib
    python3.6 -m pip install --user numpy matplotlib

## Examples
![Alt text](/examples/pcap_graph.png?raw=true "An example graph.")

examples/*.pcap generated with a [script](/pcapgraph/generate_example_pcaps.py)
 that pings and nslookups once per second. 

    pcapgraph --generate

pcap_graph.png was generated with 

    pcapgraph -c --format png --dir examples

pcap_graph.txt was generated with 

    pcapgraph -c --format txt --dir examples

## License
Apache 2. See LICENSE for more details.

## Acknowledgements
Praise be Stack Overflow!
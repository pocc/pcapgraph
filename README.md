# PcapGraph
*This has been tested on python3.5. It would be prudent to use this version 
of python or later.*

PcapGraph takes packet captures and creates a bar graph out of the start/end
timestamps. If the --compare option is used, packet captures are compared 
packet by packet to find what percentage of traffic is the same.  
## Use case
### Scenario
* You have a bunch of packet captures all from multiple interfaces on a 
network
* You need to verify that they were taken at the same time and contain the 
same packets 
 
### Solution
Use pcapgraph to visually see where there is time and traffic overlap.

## Setup & run example

    pip install -r requirements.txt
    python pcapgraph.py -c examples/simul1.pcap examples/simul2.pcap 
        examples/simul3.pcap

## Examples
![Alt text](/examples/pcap_graph.png?raw=true "An example graph.")
Above is an example graph generated with a 
[script](/examples/generate_example_pcaps.py) that pings and nslookups once 
per second. 

pcap_graph.png was generated with 

    python3 pcapgraph.py examples/simul1.pcap examples/simul2.pcap 
        examples/simul3.pcap --format png --compare

pcap_graph.txt was generated with 

    python3 pcapgraph.py examples/simul1.pcap examples/simul2.pcap 
        examples/simul3.pcap --format txt --compare

## License
Apache 2. See LICENSE for more details.

## Acknowledgements
Praise be Stack Overflow!
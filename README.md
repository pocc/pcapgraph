# PcapGraph
Creates bar graphs out of packet capture timestamps.

![Alt text](https://github.com/pocc/pcapgraph/blob/master/examples/pcap_graph.png?raw=true "An example graph.")

#### Platforms
Linux, Macos, Windows

#### Description
* Assists with flow-based troubleshooting where there are at
  least 2 pcaps. See [Usage](https://pcapgraph.readthedocs.io/en/latest/example_usage.html) 
  for detailed use cases and options.
* Create a horizontal bar graph to visualize when pcaps were taken.
* Use set operations to find patterns among multiple packet
  captures in ways that Wireshark is not able to.
* If an output format is not specified, the default behavior is to print to
  stdout and send a [matplotlib](https://matplotlib.org/) graph to the
  screen (thus the name).


Official Documentation can be found at 
[Read the Docs](https://pcapgraph.readthedocs.io/en/latest/).

## License
Apache 2.0. See LICENSE for more details.

## Acknowledgements
Praise be Stack Overflow!
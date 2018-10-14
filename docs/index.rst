.. pcapgraph documentation master file, created by
   sphinx-quickstart on Wed Oct 10 02:59:44 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

PcapGraph Manual
================
Create bar graphs out of packet capture timestamps.

About
-----

.. image:: ../examples/pcap_graph.png
   :alt: An example graph

*Three packet captures taken of the same network traffic,
staggered by 20 seconds.*

Platforms
~~~~~~~~~
Linux, Macos, Windows

Description
~~~~~~~~~~~
PcapGraph takes packet captures and creates a bar graph out of the start/end
timestamps. If the --compare option is used, packet captures are compared
packet by packet to find what percentage of traffic is the same. A list of
files, directories, and any combination thereof can be specified.

License
~~~~~~~
`Apache 2.0 <http://www.apache.org/licenses/LICENSE-2.0>`_

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   install.rst
   set_operations.rst
   pcap_timebounded.rst
   example_usage.rst
   api.rst
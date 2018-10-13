.. pcapgraph documentation master file, created by
   sphinx-quickstart on Wed Oct 10 02:59:44 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to PcapGraph's documentation!
=====================================
About
-----
Creates bar graphs out of packet capture timestamps.

![Alt text](https://github.com/pocc/pcapgraph/blob/master/examples/set_ops/pcap_graph_all.png?raw=true "An example graph.")

**NOTE**: This project requires features from **python3.6**. It would be
prudent to use
this version of python or later.*

Platforms
~~~~~~~~~
Linux, Macos, Windows

Description
~~~~~~~~~~~
PcapGraph takes packet captures and creates a bar graph out of the start/end
timestamps. If the --compare option is used, packet captures are compared
packet by packet to find what percentage of traffic is the same. A list of
files, directories, and any combination thereof can be specified.

Use case
--------
Scenario
~~~~~~~~
* You have a bunch of packet captures all from multiple interfaces on a network
* You need to verify that they were taken at the same time and contain the
  same packets

Solution
~~~~~~~~
Use pcapgraph to visually see where there is time and traffic overlap.

License
-------
Apache 2.0. See LICENSE for more details.

Table of Contents
-----------------

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   install.rst
   set_operations.rst
   pcap_timebounded.rst
   example_usage.rst
   api.rst
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
Linux, macOS, Windows

Description
~~~~~~~~~~~
* Main use case is assisting with flow-based troubleshooting where there are at
  least 3 `pcaps <https://en.wikipedia.org/wiki/Pcap>`_
* Create a horizontal bar graph to visualize when pcaps were taken.
* Use set operations to find patterns among multiple packet
  captures in ways that Wireshark is not able to.
* If an output format is not specified, the default behavior is to print to
  stdout and send a `matplotlib <https://matplotlib.org/>`_ graph to the
  screen (thus the name).

Inputs (packet captures):
  .pcapng, .pcap, .cap, .dmp, .5vw, .TRC0, .TRC1, .enc,
  .trc, .fdc, .syc, .bfr, .tr1, .snoop
Outputs:
  | **image**: display graph on screen, eps, jpeg, jpg, pdf, pgf,
    png, ps, raw, rgba, svg, svgz, tif, tiff
  | **text**: txt, stdout
  | **packet capture**: pcap

License
~~~~~~~
`Apache 2.0 <http://www.apache.org/licenses/LICENSE-2.0>`_

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   installation.rst
   cli.rst
   pcap_preparation.rst
   set_operations.rst
   example_output.rst
   generating_pcaps.rst
   background.rst
   api.rst
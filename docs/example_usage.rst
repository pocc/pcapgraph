Example Usage
=============
examples/ contains all packet captures, pngs and txt files used as examples.

Example use cases
-----------------
*All of these examples assume you want to print the graph to the screen to
visualize the problem.*

Gut check: Visualize your packet captures
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Quickly check whether pcaps were taken around the same time with a graph.
Let's say that it is necessary for packet captures to be of the same
traffic, taken on different interfaces. If it is clear from a graph that
pcaps were taken on different days, then you've saved yourself time
looking at pcaps. In this scenario, you might ask for additional pcaps
that do or do not demonstrate the issue you are troubleshooting.

.. code-block:: bash

    pcapgraph --dir examples

----

\\-\\-intersect: Find common traffic
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Use the --intersect of pcaps to find all traffic that is
shared between them. Given pcaps A-F, where A and F are the endpoints, you
can find all packets that have made it from A to F and all points in between.

.. code-block:: bash

    pcapgraph --dir examples --intersect

----

\\-\\-union: Troubleshoot broadcast storms
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Use the --union of pcaps to find the most frequent packets among all packet
capture(s). By default, using the union flag will print the top ten most
common frames in ASCII hexdump format to stdout along with their count.

In a broadcast storm, a packet capture may help identify the
devices sending the initial broadcast traffic. This information will not be
directly useful because a switching loop, once started, doesn't depend on
the instigators. It may point your troubleshooting in the
right direction to help find the loop though.

.. code-block:: bash

    pcapgraph --dir examples --union

----

-e: Find what interface traffic fails at
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Use the inverse bounded intersection to find traffic that occurred between
two frames in all packet captures, but is not shared between all of pcaps.
This can be useful when troubleshooting a flow to determine where it fails.

.. code-block:: bash

    pcapgraph --dir examples --inverse-bounded-intersect

----

Have fun with your Downloads folder
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If you take a lot of packet captures, you can use pcapgraph to visualize
your Downloads folder. Use ``pcapgraph --dir ~/Downloads`` to see what
it looks like! (It may take a while to process hundreds of packet captures).

**bash on Linux/Macos:**

.. code-block:: bash

    pcapgraph --dir ~/Downloads

**command prompt on Windows:**

.. code-block:: bat

    pcapgraph --dir %USERPROFILE%\\Downloads


----

Examples of all output formats
------------------------------
.pcap: Use all 6 set flags
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

    pcapgraph --dir examples -bdeisu --output pcap

Output
  | bounded_intersect-simul1.pcap
  | bounded_intersect-simul2.pcap
  | bounded_intersect-simul3.pcap
  | diff_bounded_intersect-simul1.pcap
  | diff_bounded_intersect-simul2.pcap
  | diff_bounded_intersect-simul3.pcap
  | intersect.pcap
  | symdiff_simul1.pcap
  | symdiff_simul2.pcap
  | symdiff_simul3.pcap
  | union.pcap


Using -x as well will remove these empty files from output:
  | symdiff_simul2.pcap
  | diff_bounded_intersect-simul1.pcap
  | diff_bounded_intersect-simul2.pcap
  | diff_bounded_intersect-simul3.pcap

----

.png: union, difference, intersect, symmetric difference
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

    pcapgraph --dir examples -disu --output png

.. image:: ../examples/set_ops/pcap_graph-disu.png

These images contain many set operations applied at the same time. This is more
of a demonstration than anything else, as there isn't much of a use case
to use all of them at the same time.

----

.txt: Basic info
~~~~~~~~~~~~~~~~

.. code-block:: bash


    pcapgraph -c --dir examples --output txt

::

    PCAP NAME           DATE 0  DATE $     TIME 0    TIME $       UTC 0              UTC $
    (100%) simul1       Sep-26  Sep-26     00:09:52  00:10:49     1537945792.6673348 1537945849.9369159
    ( 66%) simul2       Sep-26  Sep-26     00:10:12  00:11:11     1537945812.7556646 1537945871.086899
    ( 31%) simul3       Sep-26  Sep-26     00:10:32  00:11:30     1537945832.8390837 1537945890.855496


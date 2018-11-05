Using PcapGraph
===============
.. note:: `examples/` contains all packet captures, pngs and
          txt files used as examples here. You can get the examples/ directory
          by cloning this repo. You can also use
          ``pcapgraph --output generate-pcaps``, which will generate the
          starting pcaps for you (and then follow the commands below to
          create the desired file).

About
-----
All set operations use the raw frame's hex value to determine uniqueness.
This ensures that unless ARP traffic is involved (which has relatively few
fields), unique frames are going to be correctly identified as such.

.. tip:: These set operations are most useful when packet captures have
         already been filtered for the traffic that is most relevant.
         See `Pcap Preparation <pcap_preparation.html>`_ for more details.

----

Gut check: Visualize your packet captures
-----------------------------------------
.. code-block:: bash

    pcapgraph examples/ --output png --output txt

Default Image
~~~~~~~~~~~~~
Quickly check whether pcaps were taken around the same time with a graph.
Let's say that it is necessary for packet captures to be of the same
traffic, taken on different interfaces. If it is clear from a graph that
pcaps were taken on different days, then you've saved yourself time
looking at pcaps. In this scenario, you might ask for additional pcaps
that do or do not demonstrate the issue you are troubleshooting.

.. image:: ../examples/pcap_graph.png

Default Text
~~~~~~~~~~~~
Produces the same data as above, but in text.

.. code-block:: text

    PCAP NAME    DATE 0  DATE $    TIME 0    TIME $      UTC 0              UTC $
    simul1       Sep-26  Sep-26    00:09:52  00:10:49    1537945792.6673348 1537945849.9369159
    simul2       Sep-26  Sep-26    00:10:12  00:11:11    1537945812.7556646 1537945871.086899
    simul3       Sep-26  Sep-26    00:10:32  00:11:30    1537945832.8390837 1537945890.855496

Default Pcap
~~~~~~~~~~~~
**Does not exist**: no set operations are specified.

----

Union: Troubleshoot broadcast storms
------------------------------------
Union will include all unique packets, and so will include the first and last
packets of all captures.

Union Image
~~~~~~~~~~~
.. code-block:: bash

    pcapgraph examples/ --union --output png

Union image is not very useful as its bar will always span the graph.

.. image:: ../examples/set_ops/pcap_graph-union.png

Union Text
~~~~~~~~~~
.. code-block:: bash

    pcapgraph examples/ --union --output txt

For a packet capture that contains a broadcast storm, this function
will find unique packets and packet counts. This information will not be
directly useful because a switching loop, once started, doesn't depend on
the instigators. However, it may point your troubleshooting in the
right direction to help find the loop.

Use the --union of pcaps to find the most frequent packets among all packet
capture(s). By default, using the union flag will print the top ten most
common frames in ASCII hexdump format to stdout along with their count:

.. code-block:: text

    Count: 3
    0000  88 15 44 ab bf dd 24 77 03 51 13 44 08 00 45 00
    0010  00 54 7b af 40 00 40 01 92 2a 0a 30 12 90 08 08
    0020  08 08 08 00 ae 46 62 8b 00 01 e8 30 ab 5b 00 00
    0030  00 00 88 cd 0c 00 00 00 00 00 10 11 12 13 14 15
    0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
    0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
    0060  36 37

    Count: 3
    0000  88 15 44 ab bf dd 24 77 03 51 13 44 08 00 45 00
    0010  00 38 20 40 00 00 40 11 b2 b5 0a 30 12 90 0a 80
    0020  80 80 ba dc 00 35 00 24 cb 35 a3 f6 01 00 00 01
    0030  00 00 00 00 00 00 06 61 6d 61 7a 6f 6e 03 63 6f
    0040  6d 00 00 01 00 01

    Count: 3
    0000  24 77 03 51 13 44 88 15 44 ab bf dd 08 00 45 00
    0010  00 68 f7 f9 40 00 40 11 9a cb 0a 80 80 80 0a 30
    0020  12 90 00 35 ba dc 00 54 1e c2 a3 f6 81 80 00 01
    0030  00 03 00 00 00 00 06 61 6d 61 7a 6f 6e 03 63 6f
    0040  6d 00 00 01 00 01 c0 0c 00 01 00 01 00 00 00 15
    0050  00 04 b0 20 67 cd c0 0c 00 01 00 01 00 00 00 15
    0060  00 04 cd fb f2 67 c0 0c 00 01 00 01 00 00 00 15
    0070  00 04 b0 20 62 a6

    Count: 3
    0000  24 77 03 51 13 44 88 15 44 ab bf dd 08 00 45 20
    0010  00 54 ef c6 00 00 79 01 24 f3 08 08 08 08 0a 30
    0020  12 90 00 00 b6 46 62 8b 00 01 e8 30 ab 5b 00 00
    0030  00 00 88 cd 0c 00 00 00 00 00 10 11 12 13 14 15
    0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
    0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
    0060  36 37

    Count: 3
    0000  88 15 44 ab bf dd 24 77 03 51 13 44 08 00 45 00
    0010  00 54 7b fa 40 00 40 01 91 df 0a 30 12 90 08 08
    0020  08 08 08 00 74 29 62 93 00 01 e9 30 ab 5b 00 00
    0030  00 00 c1 e2 0c 00 00 00 00 00 10 11 12 13 14 15
    0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
    0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
    0060  36 37

    Count: 3
    0000  88 15 44 ab bf dd 24 77 03 51 13 44 08 00 45 00
    0010  00 38 20 8b 00 00 40 11 b2 6a 0a 30 12 90 0a 80
    0020  80 80 ea ea 00 35 00 24 69 94 d5 89 01 00 00 01
    0030  00 00 00 00 00 00 06 61 6d 61 7a 6f 6e 03 63 6f
    0040  6d 00 00 01 00 01

    Count: 3
    0000  24 77 03 51 13 44 88 15 44 ab bf dd 08 00 45 00
    0010  00 68 f7 fc 40 00 40 11 9a c8 0a 80 80 80 0a 30
    0020  12 90 00 35 ea ea 00 54 bd 23 d5 89 81 80 00 01
    0030  00 03 00 00 00 00 06 61 6d 61 7a 6f 6e 03 63 6f
    0040  6d 00 00 01 00 01 c0 0c 00 01 00 01 00 00 00 14
    0050  00 04 b0 20 62 a6 c0 0c 00 01 00 01 00 00 00 14
    0060  00 04 b0 20 67 cd c0 0c 00 01 00 01 00 00 00 14
    0070  00 04 cd fb f2 67

    Count: 3
    0000  24 77 03 51 13 44 88 15 44 ab bf dd 08 00 45 20
    0010  00 54 f1 7a 00 00 79 01 23 3f 08 08 08 08 0a 30
    0020  12 90 00 00 7c 29 62 93 00 01 e9 30 ab 5b 00 00
    0030  00 00 c1 e2 0c 00 00 00 00 00 10 11 12 13 14 15
    0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
    0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
    0060  36 37

    Count: 3
    0000  88 15 44 ab bf dd 24 77 03 51 13 44 08 00 45 00
    0010  00 54 7c 4e 40 00 40 01 91 8b 0a 30 12 90 08 08
    0020  08 08 08 00 8e 09 62 9f 00 01 ea 30 ab 5b 00 00
    0030  00 00 a6 f6 0c 00 00 00 00 00 10 11 12 13 14 15
    0040  16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
    0050  26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
    0060  36 37

    To view the content of these packets, subtract the count lines,
    add and save to <textfile>, and then run

    text2pcap <textfile> out.pcap
    wireshark out.pcap

Union Pcap
~~~~~~~~~~
.. code-block:: bash

    pcapgraph examples/ --union --output pcap

This pcap can be useful for any situation where you need to find all
unique packets. This function can be lossy with timestamps as duplicate packets
are excluded, so information can be lost.

Union file:
  `examples/set_ops/union.pcap`

.. tip:: If you want to combine pcaps without loss of duplicate packets,
         use mergecap instead. mergecap is included by default in Wireshark
         installations.

         ``mergecap (<file>) [<file>...] -w union.pcap``

----

Intersection: Find common traffic
---------------------------------
Find all packets that are shared between all packet captures.

Intersection Image
~~~~~~~~~~~~~~~~~~
The image produced in the graph can be useful in identifying where and at what
times frame overlap is occurring.

.. code-block:: bash

    pcapgraph examples/ --intersect --output png

.. image:: ../examples/set_ops/pcap_graph-intersect.png


Intersection Text
~~~~~~~~~~~~~~~~~
Intersection text will provide the percentage of packets that are the same
across multiple packet captures. Especially if packet captures are filtered
before sending to PcapGraph, this can be used to determine what percent of
traffic is failing across multiple interfaces in flow-based troubleshooting.

Intersection will alert you if the intersection has no packets.

.. code-block:: text

    SAME %      PCAP NAME
    31%          examples/simul1.pcap
    31%          examples/simul2.pcap
    31%          examples/simul3.pcap

Intersection Pcap
~~~~~~~~~~~~~~~~~
.. code-block:: bash

    pcapgraph examples/ --intersect --output pcap

Taking the intersection of multiple packet captures can provide information
on what traffic has made it through all relevant devices/interfaces.
Given pcaps A-F, where A and F are the endpoints, you can find all
packets that have made it from A to F and all points in between.

Intersection file:
  `examples/set_ops/intersect.pcap`

----

Difference: Remove shared packets
---------------------------------
Find all packets that are unique to the first packet capture.

Difference Image
~~~~~~~~~~~~~~~~
The difference image can be useful in telling at what time shared traffic
between two packet captures starts or stops.

.. code-block:: bash

    pcapgraph examples/ --difference --output png

.. image:: ../examples/set_ops/pcap_graph-difference.png

Difference Text
~~~~~~~~~~~~~~~
Difference will alert you if the difference has no packets
(i.e. the minuend packet capture is a subset of the remaining packet captures).

.. code-block:: bash

    pcapgraph examples/ --difference --output txt

Difference Pcap
~~~~~~~~~~~~~~~
.. code-block:: bash

    pcapgraph examples/ --difference --output pcap

Taking the difference between two packet captures can help find traffic
of interest that is present in one packet capture, but not another.

Difference file:
  `examples/set_ops/diff_simul1-simul3.pcap`

----

Symmetric Difference
--------------------
The symmetric difference includes only unique packets from each packet capture.


Symmetric Difference Image
~~~~~~~~~~~~~~~~~~~~~~~~~~
The symmetric difference is essentially the difference applied between the
first packet capture and every successive one.

.. code-block:: bash

    pcapgraph examples/ --symdiff --output png

.. image:: ../examples/set_ops/pcap_graph-symdiff.png


Symmetric Difference Text
~~~~~~~~~~~~~~~~~~~~~~~~~
Doesn't produce any text; however will alert if a packet capture has no
unique packets.

Symmetric Difference Pcap
~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: bash

    pcapgraph examples/ --difference --output pcap

The symmetric difference can help identify which packet captures have unique
traffic and exactly what that is. This can be useful if you have
multiple packet captures in which you want to get all unique
packets exported on a per-packet capture basis.

Difference file:
  `examples/set_ops/symdiff_simul1.pcap`
  `examples/set_ops/symdiff_simul3.pcap`

----

Timebounded Intersection
------------------------
Description
~~~~~~~~~~~
It is sometimes useful when doing flow-based troubleshooting to find all
packets between the earliest shared frame and the latest shared frame.
It may also be useful to find all traffic that is between two timestamps.
These time-bounded operations are built with, but are not bound by the
constraints of set operations.

Example Operation
~~~~~~~~~~~~~~~~~
Let 2 packet captures have the following packets and assume that traffic
originates behind the device that Initial 1 is capturing on:

The algorithm will find that packet A is the earliest common packet
and that G is the latest common packet.

+-----------+-----------+-----------+----------------+----------------+
| Initial 1 | Initial 2 | Intersect | TB Intersect 1 | TB Intersect 2 |
+===========+===========+===========+================+================+
| A         | W         | A         | A              | A              |
+-----------+-----------+-----------+----------------+----------------+
| B         | X         | B         | B              | B              |
+-----------+-----------+-----------+----------------+----------------+
| C         | A         | C         | C              | F              |
+-----------+-----------+-----------+----------------+----------------+
| D         | B         | F         | D              | M              |
+-----------+-----------+-----------+----------------+----------------+
| E         | F         | G         | E              | C              |
+-----------+-----------+-----------+----------------+----------------+
| F         | M         |           | F              | G              |
+-----------+-----------+-----------+----------------+----------------+
| G         | C         |           | G              |                |
+-----------+-----------+-----------+----------------+----------------+
| H         | G         |           |                |                |
+-----------+-----------+-----------+----------------+----------------+
| I         | L         |           |                |                |
+-----------+-----------+-----------+----------------+----------------+

(TB = Time-bounded)

.. note:: * In Pcap2, M does not exist in Pcap1
          * In Pcap2, C and F are out of order compared to Pcap1
          * The intersection does not include these interesting packets that
            are in one pcap, but note the other.

Timebound Intersection Text
~~~~~~~~~~~~~~~~~~~~~~~~~~~
**Does not exist**: None created.

Timebound Intersection Pcap
~~~~~~~~~~~~~~~~~~~~~~~~~~~
*Trim packet captures to a timeframe*

Create a packet capture intersection out of two files by finding the first and
last instances of identical frames in multiple packet captures. This is
something that you might manually do by finding a shared ip.id at the top of
both packet captures and the ip.id at the bottom of both packet captures and
then filtering out all traffic not between the frame numbers corresponding
to the packets with those ip.ids.

This function automates the described manual process.

.. code-block:: bash

    pcapgraph examples/ --bounded-intersect --output pcap

----

Inverse Timebounded Intersection
--------------------------------
Description
~~~~~~~~~~~
The difference of the intersection and the time-bounded intersection for each
packet capture. By definition, the intersection and time-bounded intersection
have the exact same starting and ending packets. What may be useful for
troubleshooting is determining in that timeframe which packets are different
across pcaps and why.

Example operation
~~~~~~~~~~~~~~~~~
+-----------+-----------+-----------+--------------------+--------------------+
| Initial 1 | Initial 2 | Intersect | Inv TB Intersect 1 | Inv TB Intersect 2 |
+===========+===========+===========+====================+====================+
| A         | W         | A         | D                  | M                  |
+-----------+-----------+-----------+--------------------+--------------------+
| B         | X         | B         | E                  |                    |
+-----------+-----------+-----------+--------------------+--------------------+
| C         | A         | C         |                    |                    |
+-----------+-----------+-----------+--------------------+--------------------+
| D         | B         | F         |                    |                    |
+-----------+-----------+-----------+--------------------+--------------------+
| E         | F         | G         |                    |                    |
+-----------+-----------+-----------+--------------------+--------------------+
| F         | M         |           |                    |                    |
+-----------+-----------+-----------+--------------------+--------------------+
| G         | C         |           |                    |                    |
+-----------+-----------+-----------+--------------------+--------------------+
| H         | G         |           |                    |                    |
+-----------+-----------+-----------+--------------------+--------------------+
| I         | L         |           |                    |                    |
+-----------+-----------+-----------+--------------------+--------------------+

(Inv TB = Inverse Time-bounded)

The key here is to subtract the intersection from each initial packet capture
to find the interesting packets that are unique to each during the intersection
time period.

Inverse Timebound Intersection Text
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
**Does not exist**: None created.

Inverse Timebounded Intersect Pcap
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
*Find what interface traffic fails at*

Use the inverse bounded intersection to find traffic that occurred between
two frames in all packet captures, but is not shared between all of pcaps.
This can be useful when troubleshooting a flow to determine where it fails.

.. code-block:: bash

    pcapgraph examples/ --inverse-bounded --output pcap

----

Have fun with your Downloads folder
-----------------------------------
If you take a lot of packet captures, you can use pcapgraph to visualize
your Downloads folder. Use ``pcapgraph --dir ~/Downloads`` to see what
it looks like! (It may take a while to process hundreds of packet captures).

**bash on Linux/Macos:**

.. code-block:: bash

    pcapgraph ~/Downloads/

**command prompt on Windows:**

.. code-block:: bat

    pcapgraph %USERPROFILE%\\Downloads

----

Examples of all output formats
------------------------------
.. comment filler for horizontal rule.

----

.pcap: Use all 6 set flags
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

    pcapgraph examples/ -bdeisu --output pcap

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

.png: union, difference, intersect, symmetric difference
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

    pcapgraph examples/ -disu --output png

.. image:: ../examples/set_ops/pcap_graph-disu.png

These images contain many set operations applied at the same time. This is more
of a demonstration than anything else, as there isn't much of a use case
to use all of them at the same time.


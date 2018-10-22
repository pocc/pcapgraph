Using PcapGraph
===============
.. note:: `examples/` contains all packet captures, pngs and
          txt files used as examples here.

About
-----
All set operations use the raw frame's hex value to determine uniqueness.
This ensures that unless ARP traffic is involved (which has relatively few
fields), unique frames are going to be correctly identified as such.

.. tip:: These set operations are most useful when packet captures have
         already been filtered for the traffic that is most relevant.
         See `Pcap Preparation <pcap_preparation.html>`_ for more details.

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

.. code-block:: bash

    pcapgraph examples/ --union --output png --output txt --output pcap

Union Image
~~~~~~~~~~~
Union image is not very useful as its bar will always span the graph.

.. image:: ../examples/set_ops/pcap_graph-union.png

Union Text
~~~~~~~~~~
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
This pcap can be useful for any situation where you need to find all
unique packets. This function can be lossy with timestamps as duplicate packets
are excluded, so information can be lost.

Union file:
  `examples/set_ops/union.pcap`

.. tip:: If you want to combine pcaps without loss of duplicate packets,
         use mergecap instead. mergecap is included by default in Wireshark
         installations.

         ``mergecap (<file>) [<file>...] -w union.pcap``


-e: Find what interface traffic fails at
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Use the inverse bounded intersection to find traffic that occurred between
two frames in all packet captures, but is not shared between all of pcaps.
This can be useful when troubleshooting a flow to determine where it fails.

.. code-block:: bash

    pcapgraph examples/ --inverse-bounded-intersect

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


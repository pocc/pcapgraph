Timebounded Operations
======================
It is sometimes useful when doing flow-based troublesohoting to find all
packets between the earliest shared frame and the latest shared frame.
It may also be useful to find all traffic that is between two timestamps.
These timebounded operations are built with, but are not bound by the
constraints of set operations.

.. tip:: These set operations are most useful when the packet captures have
         already been filtered for the traffic that is most relevant.
         The smaller the packet captures are, the faster pcapgraph is at
         processing them and the easier it will be to draw conclusions from
         exported graphs and packet capures.

Timebounded Intersection
------------------------
Description
~~~~~~~~~~~
Create a packet capture intersection out of two files by finding the first and
last instances of identical frames in multiple packet captures.

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

(TB = Timebounded)

.. note:: * In Pcap2, M does not exist in Pcap1
          * In Pcap2, C and F are out of order compared to Pcap1
          * The intersection does not include these interesting packets that
            are in one pcap, but note the other.

Inverse Timebounded Intersection
--------------------------------
Description
~~~~~~~~~~~
The difference of the intersection and the timebounded intersection for each
packet capture. By definition, the intersection and timebounded intersection
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

(Inv TB = Inverse Timebounded)

The key here is to subtract the intersection from each initial packet capture
to find the interesting packets that are unique to each during the intersection
time period.
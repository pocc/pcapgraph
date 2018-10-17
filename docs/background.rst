Further Reading
===============
Set Theory
----------
.. note:: If you want a set primer, you may want to check out the
          `set operations <https://en.wikipedia.org/wiki/Set_(mathematics)
          #Basic_operations>`_ Wikipedia article.

Basic Set Operations
~~~~~~~~~~~~~~~~~~~~
The terminology used here is based on set theory. For example, given sets

    | A = (1, 2, 3)
    | B = (2, 3, 4)
    | C = (3, 4, 5)

+----------------------+----------------------+---------------------------------------------------+
| Set Operation        | Applied to (A, B, C) | Definition                                        |
+======================+======================+===================================================+
| Union                |  (1, 2, 3, 4, 5)     | All unique elements.                              |
+----------------------+----------------------+---------------------------------------------------+
| Intersection         | \(3\)                | All common elements.                              |
+----------------------+----------------------+---------------------------------------------------+
| Difference           | \(1\)                | All elements in the first set not in latter sets. |
+----------------------+----------------------+---------------------------------------------------+
| Symmetric Difference | (1, 5)               | All elements unique to only one set.              |
+----------------------+----------------------+---------------------------------------------------+

Packet Uniqueness
~~~~~~~~~~~~~~~~~
By definition, a set only has unique elements. The result of any
set operation is also a set. This program uses the entire frame as an
element to determine uniqueness, which ensures fewer duplicates. The FCS
may be stripped by the NIC depending on network drivers, and so may not
necessarily be available for packet identification (I have only seen Juniper
devices take packet captures that contain the FCS).

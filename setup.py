#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2018 Ross Jacobs All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""setup file."""
from distutils.core import setup
from pcapgraph import __version__

setup(name='PcapGraph',
      version=__version__,
      description='Create a graph out of packet captures',
      author='Ross Jacobs',
      author_email='whim42+pcapgraph@gmail.com',
      url='https://www.github.com/pocc/pcapgraph/',
      license='Apache 2',
      packages=['pcapgraph'],
      python_requires='>=3.6',
      entry_points={
          'console_scripts':
              ['pcapgraph = pcapgraph.pcapgraph:main']}
      )

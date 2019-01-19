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

# Creating this so I don't need to memorize PyPI commands.

# Use correct python. Windows does not have python ambiguity.
ifneq ($(OS),Windows_NT)
ifneq (,$(shell which python3))
PYTHON:=python3
endif
else
PYTHON:=python
endif

PYTHON_PIP_VER:=$(lastword $(shell $(PYTHON) -m pip -V))
.DEFAULT: install
.PHONY: clean install test tests lint testpypi testinstall pypi onefile onedir html pyinstaller

clean:
	$(RM) -r dist/ build/ docs/_build *.png *.pcap *.pcapng

# Triggers `python setup.py sdist` prior to install.
install: clean
	@echo "INFO: Your pip's python version ($(PYTHON_PIP_VER), 3.5+ required"
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install --user .

# Install missing dependencies
pipdep:
	$(PYTHON) -m pip install --user sphinx pyinstaller twine flake8 pylint yapf pytest

# Use PyInstaller to generate a single file containing all libraries
# matplotlib is 15MB, numpy is 13MB for executable size
onefile: clean pyinstaller
	$(PYTHON) -m PyInstaller gateway.py -n pcapgraph --onefile --exclude-module PyQt5 \
	--exclude-module PyQt4 --exclude-module PySide --clean -y

# Use PyInstaller to generate a dir ideal for a tarfile
onedir: clean pyinstaller
	$(PYTHON) -m PyInstaller gateway.py -n pcapgraph --onedir --exclude-module PyQt5 \
	--exclude-module PyQt4 --exclude-module PySide --clean -y

# Run all tests in test directory
tests: test
test: clean
	$(PYTHON) -m pytest tests

# Lint using flake8, pylint, yapf
lint:
	$(PYTHON) -m flake8 pcapgraph tests
	$(PYTHON) -m pylint pcapgraph tests
	$(PYTHON) -m yapf -pri pcapgraph

# Use this first before uploading to pypi to verify that it uploaded correctly.
testpypi: clean test lint
	python setup.py sdist
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*

# After testpypi, verify that it installs and runs correctly
testinstall:
	$(PYTHON) -m pip install -U --user --index-url \
	https://test.pypi.org/simple/ pcapgraph

# Use this when you are sure that the test upload (above) looks good.
pypi: clean install test lint
	@echo "If this fails, increase __version__"
	$(PYTHON) -m twine upload dist/*

# Trigger Sphinx Makefile in docs/ and open them in a web browser
open:
	cd docs && make open
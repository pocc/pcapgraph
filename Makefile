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



.DEFAULT: clean
.PHONY: clean install test lint testpypi installtestpypi pypi

clean:
	$(RM) -r dist/ build/

# Install locally to dist/
install:
	python3.6 setup.py sdist

# Run all tests in test directory
test:
	pytest tests

# Lint using flake8, pylint, yapf
lint:
	flake8
	pylint
	yapf -pri

# Use this first before uploading to pypi to verify that it uploaded correctly.
testpypi: clean install
	twine upload --repository-url https://test.pypi.org/legacy/ dist/*

# After testpypi, verify that it installs and runs correctly
installtestpypi:
	python3.6 -m pip install -U --user --index-url https://test.pypi.org/simple/ pcapgraph

# Use this when you are sure that the test upload (above) looks good.
pypi: clean install
	@echo "If this fails, increase __version__"
	twine upload dist/*

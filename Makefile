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
.PHONY: clean make

clean:
	$(RM) -r dist/ build/

upload: clean
	@echo "If this fails, increase __version__"
	python3.6 setup.py sdist
	twine upload dist/*

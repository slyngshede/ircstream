"""IRCStream — MediaWiki RecentChanges → IRC gateway.

IRCStream is a simple gateway to the MediaWiki recent changes feed, from the
IRC protocol. It was written mainly for compatibility reasons, as there are a
number of legacy clients in the wild relying on this interface.
"""

# Copyright © Faidon Liambotis
# Copyright © Wikimedia Foundation, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY CODE, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-FileCopyrightText: Faidon Liambotis
# SPDX-FileCopyrightText: Wikimedia Foundation
# SPDX-License-Identifier: Apache-2.0

from ._version import __version__
from .main import run

__all__ = [
    "__version__",
    "run",
]

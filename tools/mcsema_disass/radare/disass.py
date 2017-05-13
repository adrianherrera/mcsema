#!/usr/bin/env python
# Copyright (c) 2017 Adrian Herrera
# Copyright (c) 2017 Trail of Bits, Inc.
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

import traceback
import sys

from .get_cfg import get_cfg


def execute(args, command_args):
    """Execute radare using r2pipe
    (https://github.com/radare/radare2/wiki/R2PipeAPI). Because we are using
    r2pipe, there is no need to create a subprocess. We can just start the
    pipe and communicate with Radare over the pipe. `command_args` contains
    unparsed arguments passed to `mcsema_disass`. This script may handle extra
    arguments."""

    try:
        # Transform the argspace.Namespace object into a dict. Remove the
        # binary from the dict so that we can use it directly
        args_dict = vars(args)
        binary = args_dict.pop("binary")

        return get_cfg(binary, command_args, **args_dict)
    except Exception:
        sys.stderr.write(traceback.format_exc())
        return 1

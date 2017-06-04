# Copyright (c) 2017 Adrian Herrera
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

"""
This module contains utility functions specific to Radare.
"""


import r2pipe


__all__ = ["r2_init",
           "r2_get_section",
           "r2_get_function",
           "r2_do_cmd_at_pos",
          ]


def r2_init(path):
    """Load the binary at `path` into Radare."""
    r2 = r2pipe.open(path)
    r2.cmd("aaa")

    return r2


_SECTION_MAP = dict()


def r2_get_section(r2, sec_name, default=None):
    """Cache the sections as a map for more efficient lookups by name."""
    global _SECTION_MAP

    if _SECTION_MAP:
        return _SECTION_MAP.get(sec_name, default)

    # Build the section map if it does not already exist
    for sec in r2.cmdj("Sj"):
        name = sec.pop("name")
        _SECTION_MAP[name] = sec

    return _SECTION_MAP.get(sec_name, default)


_FUNCTION_MAP = dict()


def r2_get_function(r2, func_name, check_externals=False, default=None):
    """Get the start address of a function."""
    global _FUNCTION_MAP

    def get_func(func_name, check_externals=False, default=None):
        """Retrieve a function from the `_FUNCTION_MAP`."""
        # Check for the function name directly
        func = _FUNCTION_MAP.get(func_name)
        if func:
            return func

        # Check the symbol table
        func = _FUNCTION_MAP.get("sym.{}".format(func_name))
        if func:
            return func

        if not check_externals:
            # If we are not checking external functions and we have reached
            # this point, the function does not exist
            return default

        for prefix in ("sym.impl", "sub"):
            # Now check if the function is external
            func = _FUNCTION_MAP.get("{}.{}".format(prefix, func_name))
            if func:
                return func

        return default

    if _FUNCTION_MAP:
        return get_func(func_name, check_externals, default)

    # Build the function map if it does not already exist
    for func in r2.cmdj("aflj"):
        name = func.pop("name")
        _FUNCTION_MAP[name] = func

    return get_func(func_name, check_externals, default)


def r2_do_cmd_at_pos(r2, addr, cmd):
    """Seek to a specific address so that we can perform a command there, then
    return to our original position."""
    _r2_seek(r2, addr)

    if cmd.split(" ")[0][-1] == "j":
        # Execute a command that produces JSON output
        res = r2.cmdj(cmd)
    else:
        res = r2.cmd(cmd)
    # Undo the seek
    r2.cmd("s-")

    return res


def _r2_seek(r2, addr):
    """Seek to a specific address and check that the seek was successful. Throw
    an exception if it wasn't."""
    new_addr = int(r2.cmd("s {:#x}; s".format(addr)), 16)
    if addr != 0x00 and new_addr == 0x00:
        raise Exception("Failed to see to {:#x}".format(addr))

    return new_addr

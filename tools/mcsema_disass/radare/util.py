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


import struct

from .r2_util import r2_do_cmd_at_pos, r2_get_section


_NOT_CODE_ADDRS = set()


def is_code(r2, addr):
    """Returns `True` if `addr` belongs to some code segment."""
    global _NOT_CODE_ADDRS
    if addr in _NOT_CODE_ADDRS:
        return False

    # Get the current section and its flags
    sec = r2_do_cmd_at_pos(r2, addr, "S.j")[0]
    sec_flags = r2_get_section(r2, sec["name"]).get("flags")

    return sec_flags[-1] == "x"


# XXX try_mark_as_code - no idea how to do this in Radare >_<


def mark_as_not_code(addr):
    global _NOT_CODE_ADDRS
    _NOT_CODE_ADDRS.add(addr)


def read_bytes(r2, start, end):
    # Radare equivalent of the `read_bytes_slowly` function
    length = start - end

    asm_bytes = get_address_size_in_bytes(r2)
    offset = 0
    num_bytes_read = 0
    bytestr = ""

    while num_bytes_read < length:
        # The "*" command will read "asm.bits" from the given address
        val = int(r2.cmd("* {:#x}".format(start + offset * asm_bytes)), 16)

        # Now separate the "asm.bits"-sized integer into separate bytes. We
        # also need to break early for the case when we hit the end address
        # outside of the "asm.bits" boundary
        while val != 0 and num_bytes_read < length:
            bytestr = "%s%s" % (bytestr, chr(val & 0xFF))
            num_bytes_read += 1
            val >>= 8
        offset += 1

    return bytestr


def read_byte(r2, addr):
    byte = read_bytes(r2, addr, addr + 1)
    return ord(byte)


def read_dword(r2, addr):
    bytestr = read_bytes(r2, addr, addr + 4)
    return struct.unpack("<L", bytestr)[0]


def read_qword(r2, addr):
    bytestr = read_bytes(r2, addr, addr + 8)
    return struct.unpack("<Q", bytestr)[0]


_NOT_EXTERNAL_SEGMENTS = set()
_EXTERNAL_SEGMENTS = set()


def is_external_segment(r2, addr):
    """Returns `True` if the segment containing `addr` looks to be solely
    containng external references."""
    global _NOT_EXTERNAL_SEGMENTS

    seg = r2_do_cmd_at_pos(r2, addr, "S.j")[0]

    base_addr = seg["start"]
    if base_addr in _NOT_EXTERNAL_SEGMENTS:
        return False

    if base_addr in _EXTERNAL_SEGMENTS:
        return True

    seg_name = seg["name"].lower()
    if ".got" in seg_name or ".plt" in seg_name:
        _EXTERNAL_SEGMENTS.add(base_addr)
        return True

    # TODO check for external definitions
    raise NotImplementedError()

    _NOT_EXTERNAL_SEGMENTS.add(base_addr)
    return False


def is_internal_code(r2, addr):
    if is_external_segment(r2, addr):
        return False

    if is_code(r2, addr):
        return True

    # Find stray 0x90 (NOP) bytes in .text that IDA thinks are data items
    #
    # XXX Not sure if this is an issue in Radare, but let's check anyway
    if read_byte(r2, addr) == 0x90:
        if not try_mark_as_code(r2, addr):
            return False
        return True

    return False


def get_address_size_in_bits(r2):
    """Returns the available address size."""
    return r2.cmdj("ej").get("asm.bits")


def get_address_size_in_bytes(r2):
    return get_address_size_in_bits(r2) / 8


def get_symbol_name(r2, addr):
    """Tries to get the name of a symbol."""
    func_info = r2.cmdj("afij {:#x}".format(addr))

    if func_info:
        # Radare applies varies prefixes to external functions/symols. Remove
        # them
        name = func_info["name"].split(".")[-1]

        return name

    return ""


def get_reference_target(r2, addr):
    xrefs = r2.cmdj("axfj {:#x}".format(addr))

    for xref in xrefs:
        return xref

    return None

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


from mcsema_disass.common.refs import Reference


_REFS = {}
_HAS_NO_REFS = set()
_NO_REFS = tuple()
_ENABLE_CACHING = False


def get_all_references_from(r2, addr):
    """Return the set of all references from `addr` to anything."""
    all_refs = set()

    # THe axf command includes both code and data references
    for xref in r2.cmdj('axfj 0x%x' % addr):
        if xref["from"] == addr:
            all_refs.add(xref["to"])

    return all_refs


# This is a real hack. It can take a few tries to really find referenes, so
# we'll only enable reference caching after we do some processing of segments.
# Hopefully after such processing, we will have discovered item heads that
# Radare hadn't previously identified
def enable_reference_caching():
    global _ENABLE_CACHING
    _ENABLE_CACHING = True


def get_instruction_references(r2, inst, binary_is_pie=False):
    """Get a list of referenecs from an instruction."""
    global _ENABLE_CACHING

    if _ENABLE_CACHING:
        if inst["offset"] in _HAS_NO_REFS:
            return _NO_REFS

        if inst["offset"] in _REFS:
            return _REFS[inst["offset"]]

    all_refs = get_all_references_from(r2, inst["offset"])

    raise NotImplementedError()

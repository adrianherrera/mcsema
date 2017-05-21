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


from mcsema_disass.common.util import DEBUG, DEBUG_PUSH, DEBUG_POP
from .r2_util import r2_do_cmd_at_pos

# Note: Radare uses the term "section", rather than segment

def _decode_segment_instructions(r2, seg, binary_is_pie):
    """Tries to find all jump tables ahead of time. A side-effect of this is to
    create a decoded instruction and jump table cache. The other side-effect is
    that the decoding of jump tables will *remove* some cross-references."""
    code = r2_do_cmd_at_pos(r2, seg["vaddr"], "pDj %d" % seg["vsize"])


def process_segments(r2, binary_is_pie):
    """Pre-process a segment and try to fill in as many cross-references as is
    possible."""

    # Start by going through all instructions. One result is that we should
    # find and identify jump tables, which we need to do so that we don't
    # incorrectly categorize some things as strings.
    for sec in r2.cmdj("Sj"):
        sec_addr = sec["vaddr"]
        sec_flags = sec["flags"]
        sec_name = sec["name"]

        # Radare has no notion of which sections are code. Therefore let's just
        # look for executable sections
        if sec_flags[-1] == "x" and sec_flags[0] != "m":
            DEBUG("Looking for instructions in segment {}".format(sec_name))
            DEBUG_PUSH()
            _decode_segment_instructions(r2, sec, binary_is_pie)
            DEBUG_POP()

    # Now go through the data segments and look for strings and missing
    # cross-references.
    for sec in r2.cmdj("Sj"):
        # TODO finish this
        raise NotImplementedError()

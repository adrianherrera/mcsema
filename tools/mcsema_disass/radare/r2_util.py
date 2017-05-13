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


def r2_do_cmd_at_pos(r2, pos, cmd):
    """Seek to a specific position so that we can perform a command there, then
    return to our original position."""
    _r2_seek(r2, pos)
    if cmd[-1] == "j":
        # Execute a command that produces JSON output
        res = r2.cmdj(cmd)
    else:
        res = r2.cmd(cmd)
    # Undo the seek
    r2.cmd("s-")

    return res


def _r2_seek(r2, pos):
    """Seek to a specific position and check that the seek was successful.
    Throw an exception if it wasn't."""
    actual_pos = int(r2.cmd("s {};s".format(pos)), 16)
    if pos != 0x00 and actual_pos == 0x00:
        raise Exception("Failed to see to {}".format(pos))

    return actual_pos

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


class Reference(object):
    __slots__ = ('offset', 'ea', 'symbol', 'type')

    INVALID = 0
    IMMEDIATE = 1
    DISPLACEMENT = 2
    MEMORY = 3
    CODE = 4

    TYPE_TO_STR = {
        INVALID: "(null)",
        IMMEDIATE: "imm",
        DISPLACEMENT: "disp",
        MEMORY: "mem",
        CODE: "code",
    }

    def __init__(self, ea, offset):
        self.offset = offset
        self.ea = ea
        self.symbol = ""
        self.type = self.INVALID

    def __str__(self):
        return "({} {} {})".format(is_code(self.ea) and "code" or "data",
                                   self.TYPE_TO_STR[self.type],
                                   self.symbol or "0x{:x}".format(self.ea))

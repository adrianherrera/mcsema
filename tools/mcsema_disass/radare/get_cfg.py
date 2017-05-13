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


import argparse
import os
import traceback

# Note: The bootstrap file will copy CFG_pb2.py into the common dir!!
from mcsema_disass.common import CFG_pb2

from mcsema_disass.common.util import *
from . import r2_init
from .segment import *
from .util import *


tools_disass_radare_dir = os.path.dirname(__file__)
tools_disass_dir = os.path.dirname(tools_disass_radare_dir)

EXTERNAL_FUNCS_TO_RECOVER = {}
EXTERNAL_VARS_TO_RECOVER = {}

RECOVERED_ADDRS = set()
ACCESSED_VIA_JMP = set()

# Map of external functions names to a tuple containing information like the
# number of arguments and calling convention of the function.
EMAP = {}

# Map of external variable names to their sizes, in bytes.
EMAP_DATA = {}

# `True` if we are getting the CFG of a position independent executable. This
# affects heuristics like trying to turn immediate operands in instructions
# into references into the data.
PIE_MODE = False

# Name of the operating system that runs the program being lifted. E.g. if
# we're lifting an ELF then this will typically be `linux`.
OS_NAME = ""

# Set of substrings that can be found inside of symbol names that are usually
# signs that the symbol is external. For example, `stderr@@GLIBC_2.2.5` is
# really the external `stderr`, so we want to be able to chop out the `@@...`
# part to resolve the "true" name,
EXTERNAL_NAMES = ("@@GLIBC_",)


def is_ELF_program(r2):
    """Returns `True` if the type of the program being recovered is an ELF."""
    return r2.cmdj("ij").get("bin").get("bintype") == "elf"


def is_linked_ELF_program(r2):
    """Returns `True` if this is an ELF binary (as opposed to an ELF object
    file)."""
    info = r2.cmdj("ij")
    return info.get("bin").get("bintype") == "elf" and \
        not info.get("core").get("type").startswith("REL")


def is_ELF_got_pointer(r2, addr):
    """Returns `True` if this is a pointer to a pointer stored in the
    `.got` section of an ELF binary. For example, `__gmon_start___ptr` is
    a pointer in the `.got` that will be fixed up to contain the address of
    the external function `__gmon_start__`. We don't want to treat
    `__gmon_start___ptr` as external because it is really a sort of local
    variable that will will resolve with a data cross-reference."""
    sec_info = r2_do_cmd_at_pos(r2, addr, "S.j")[0]["name"]
    if ".got" not in sec_name:
        return False

    name = get_symbol_name(r2, addr)
    if not name.endswith("_ptr"): # XXX Is "_ptr" a thing in Radare?
        return False

    target_addr = get_reference_target(r2, addr)
    target_name = get_true_external_name(r2, get_symbol_name(r2, target_addr))

    if target_name not in name:
        return False

    return is_referenced_by(r2, target_addr, addr)


def is_ELF_got_pointer_to_external(r2, addr):
    """Similar to `is_ELF_got_pointer`, but requires that the eventual target
    of the pointer is an external."""
    if not is_ELF_got_pointer(r2, addr):
        return False

    target_addr = get_reference_target(r2, addr)

    return is_external_segment(r2, target_addr)


_FIXED_EXTERNAL_NAMES = {}


def get_true_external_name(r2, fn):
    """Tries to get the 'true' name of `fn`. This removes things like
    ELF-versioning from symbols."""
    if not fn:
        return ""

    orig_fn = fn
    if fn in _FIXED_EXTERNAL_NAMES:
        return _FIXED_EXTERNAL_NAMES[orig_fn]

    if fn in EMAP:
        return fn

    if fn in EMAP_DATA:
        return fn

    # TODO(pag): Is this a macOS or Windows thing?
    if not is_linked_ELF_program(r2) and fn[0] == "_":
        return fn[1:]

    # TODO finish this


# TODO A bunch of functions in here


def recover_instruction(r2, M, B, addr):
    """Recover an instruction, adding it to its parent block in the CFG."""
    # TODO
    pass


def recover_basic_block(r2, M, F, block_addr):
    """Add in a basic block to a specific function in the CFG."""
    # TODO
    pass


def analyze_jump_table_targets(r2, inst, new_addrs, new_func_addrs):
    """Function recovery is an iterative process. Sometimes we'll find things
    in the entries of the jump table that we need to go mark as code to be
    added into the CFG."""
    # TODO
    pass


def recover_function(r2, M, func_addr, new_func_addrs, entrypoints):
    """Decode a function and store it, all of its basic blocks, and all of
    their instructions into the CFG file."""
    # TODO
    pass


def find_default_function_heads(r2):
    """Loop through every function, to discover the heads of all blocks that
    IDA recognizes. This will populate some global sets in `flow.py` that
    will help distinguish block heads."""
    # TODO
    pass


def recover_segment_variables(r2, M, S, seg_addr, seg_end_addr):
    """Look for named locations pointing into the data of this segment, and
    add them to the protobuf."""
    # TODO
    pass


def recover_segment_cross_references(r2, M, S, seg_addr, seg_end_addr):
    """Goes through the segment and identifies fixups that need to be
    handled by the LLVM side of things."""
    # TODO
    pass


def recover_segment(r2, M, seg_addr):
    """Recover the data and cross-references from a segment. The data of a
    segment is stored verbatim within the protobuf, and accompanied by a
    series of variable and cross-reference entries."""
    # TODO
    pass


def recover_segments(r2, M):
    """Recover all non-external segments into the CFG module."""
    # TODO
    pass


def recover_external_functions(r2, M):
    """Recover the named external functions (e.g. `printf`) that are referenced
    within this binary."""
    # TODO
    pass


def recover_external_variables(r2, M):
    """Reover the named external variables (e.g. `stdout`) that are referenced
    within this binary."""
    # TODO
    pass


def recover_external_symbols(r2, M):
    recover_external_functions(r2, M)
    recover_external_variables(r2, M)


def try_identify_as_external_function(r2, addr):
    """Try to identify a function as being an external function."""
    # TODO
    pass


def identify_external_symbols(r2):
    """Try to identify external functions and variables."""
    # TODO
    pass


def identify_progam_entrypoints(r2, func_addrs):
    """Identify all entrypoints into the program. This is pretty much any
    externally visable function."""
    symbols = r2.cmdj('isj')
    entries = [symbol for symbol in symbols if symbol['type'] == 'FUNC']
    entrypoints = set()

    for entry in entries:
        # TODO finish this
        pass

    return entrypoints


def recover_module(r2, entrypoint):
    global EMAP
    global EXTERNAL_FUNCS_TO_RECOVER

    M = CFG_pb2.Module()
    name = os.path.basename(r2.cmdj("ij").get("core").get("file"))
    M.name = name.format("utf-8")
    DEBUG("Recovering module {}".format(name))

    process_segments(r2, PIE_MODE)
    func_addrs = find_default_function_heads(r2)

    recovered_fns = 0

    identify_external_symbols(r2)

    entrypoints = identify_program_entrypoints(r2, func_addrs)
    entrypoints = set()
    entry_info = r2.cmdj("afij {}".format(entrypoint))
    if entry_info:
        entrypoints.add(entry_info[0]["offset"])

    # Process and recover functions.
    while len(func_addrs) > 0:
        func_addr = func_addrs.pop()
        if func_addr in RECOVERED_ADDRS or func_addr in EXTERNAL_FUNCS_TO_RECOVER:
            continue

        RECOVERED_ADDRS.add(func_addr)

        if try_identify_as_external_function(r2, func_addr):
            DEBUG("ERROR: External function {:x} not previously identified".format(func_addr))
            continue

        if not is_internal_code(r2, func_addr):
            DEBUG("ERROR: Function address not code: {:x}".format(func_addr))
            continue

        if is_external_segment(r2, func_addr):
            continue

        recover_function(r2, M, func_addr, func_addrs, entrypoints)
        recovered_fns += 1

    if recovered_fns == 0:
        DEBUG("COULD NOT RECOVER ANY FUNCTIONS")
        return

    recover_segments(r2, M)
    recover_external_symbols(r2, M)

    DEBUG("Recovered {0} functions.".format(recovered_fns))
    return M


def get_cfg(binary, command_args, **args):
    # Parse the `command_args`. Only the arguments that were not parsed in
    # `disass.py` need to be handled here
    parser = argparse.ArgumentParser()
    parser.add_argument("--std-defs", action="append", type=str, default=[],
                        help="std_defs file: definitions and calling "
                             "conventions of imported functions and data")
    parser.add_argument("-z", "--syms", type=argparse.FileType("r"),
                        default=None, help="File containing <name> <address> "
                                           "pairs of symbols to pre-define.")
    parser.add_argument("--pie-mode", action="store_true", default=False,
                        help="Assume all immediate values are constants "
                             "(useful for ELFs built with -fPIE)")
    parsed_command_args = parser.parse_args(args=command_args)

    # Combine the args parsed in `disass.py` and the command args parsed here
    args.update(vars(parsed_command_args))

    if args.get("log_file", os.devnull) != os.devnull:
        log_file = open(args["log_file"], "w")
        INIT_DEBUG_FILE(log_file)
        DEBUG("Debugging is enabled.")
    else:
        log_file = None

    # We don't need to checkout address size in Radare

    if args.get("pie_mode"):
        DEBUG("Using PIE mode.")

        global PIE_MODE
        PIE_MODE = True

    global EMAP, EMAP_DATA
    EMAP = {}
    EMAP_DATA = {}

    # Try to find the defs file for this OS
    global OS_NAME
    OS_NAME = args["os"]
    os_defs_file = os.path.join(tools_disass_dir, "defs",
                                "{}.txt".format(args["os"]))
    if os.path.isfile(os_defs_file):
        args["std_defs"].insert(0, os_defs_file)

    # Load in all defs files, include custom ones.
    for defsfile in args["std_defs"]:
        with open(defsfile, "r") as df:
            DEBUG("Loading Standard Definitions file: {0}".format(defsfile))
            # TODO parse defs file

    DEBUG("Starting analysis")
    try:
        # Pre-define a bunch of symbol names and their addresses. Useful when
        # reading a core dump.
        if args.get("syms"):
            # TODO handle this
            pass

        # Initialize Radare
        r2 = r2_init(binary)

        # Recover the module as a protobuf
        M = recover_module(r2, args["entrypoint"])

        with open(args["output"], "wb") as output:
            DEBUG("Saving to: {0}".format(output.name))
            output.write(M.SerializeToString())
    except Exception as e:
        DEBUG(str(e))
        DEBUG(traceback.format_exc())
    finally:
        if r2:
            r2.quit()

        if log_file:
            log_file.close()

    return 0

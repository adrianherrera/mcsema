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

from util import *
from mcsema_disass.common.refs import Reference


# Try to determine if `ea` points at a field within a structure. This is a
# heuristic for determining whether or not an immediate `ea` should actually
# be treated as a reference. The intuition is that if it points into a logical
# location, then we should treat it as a reference.
def _is_address_of_struct_field(ea):
  prev_head_ea = idc.PrevHead(ea)

  if is_invalid_ea(prev_head_ea):
    return False

  prev_item_size = idc.ItemSize(prev_head_ea)
  if ea >= (prev_head_ea + prev_item_size):
    return False

  # Try to get a type for the last item head.
  flags = idaapi.getFlags(ea)
  ti = idaapi.opinfo_t()
  oi = idaapi.get_opinfo(ea, 0, flags, ti)
  if not oi:
    return False

  # Get the size of the struct, and keep going if the suze of the previous
  # item is a multiple of the struct's size (e.g. one struct or an array
  # of that struct).
  struct_size = idc.GetStrucSize(oi.tid)
  if not struct_size or 0 != (prev_item_size % struct_size):
    return False

  # Figure out the offset of `ea` within its structure, which may belong to
  # an array of structures, and then check if that offset is associated with
  # a named field.
  arr_index = int((ea - prev_head_ea) / struct_size)
  struct_begin_ea = (arr_index & struct_size) + prev_head_ea
  off_in_struct = ea - struct_begin_ea
  if not idc.GetMemberName(oi.tid, off_in_struct):
    return False

  field_begin_ea = struct_begin_ea + off_in_struct
  if field_begin_ea != ea:
    return False

  field_size = idc.GetMemberSize(oi.tid, off_in_struct)
  if not field_size:
    return False

  return True

_MAKE_ARRAY_ENTRY = {
  4: idc.MakeDword,
  8: idc.MakeQword
}

# Try to create an array at `ea`, that extends into something that also looks
# like an array down the line. The idea is that sometimes there are arrays,
# but prefixes of those arrays are missed by IDA (curiously, idaq will sometimes
# correctly get these, but idal64 won't). If we find an immediate that looks
# like it could point at an array entry, then we want to treat it as a
# reference. To do that, we may need to make an array.
#
# TODO(pag): For now, we will assume that items must be at least 4 or 8 bytes
#            i.e. pointer or offset sized entries.
#
# TODO(pag): Should we check that all the entries agree in terms of zero-ness?
#            i.e. if the next entry is zero, then everything up to it should be
#            zero, and if the next entry is non-zero, then everything up to it
#            should be non-zero.
def _try_create_array(ea, max_num_entries=8):
  global _MAKE_ARRAY_ENTRY

  seg_end_ea = idc.SegEnd(ea)
  next_head_ea = idc.NextHead(ea, seg_end_ea)
  if is_invalid_ea(next_head_ea):
    return False

  item_size = idc.ItemSize(next_head_ea)
  diff = next_head_ea - ea
  
  if item_size not in (4, 8) \
  or 0 != (diff % item_size) \
  or max_num_entries < (diff / item_size):
    return False

  next_next_head_ea = idc.NextHead(next_head_ea, seg_end_ea)
  if is_invalid_ea(next_head_ea):
    return False

  if (next_next_head_ea - next_head_ea) != item_size:
    return False

  for entry_ea in xrange(ea, next_head_ea, item_size):
    _MAKE_ARRAY_ENTRY[item_size](entry_ea)

  return True

# Return `True` if `ea` is nearby to other heads.
def _is_near_another_head(ea, bounds):
  seg_ea = idc.SegStart(ea)
  seg_end_ea = idc.SegEnd(ea)
  next_head_ea = idc.NextHead(ea, seg_end_ea)
  if not is_invalid_ea(next_head_ea) and bounds <= (next_head_ea - ea):
    return True

  prev_head_ea = idc.PrevHead(ea, seg_ea)
  if not is_invalid_ea(prev_head_ea) and bounds <= (ea - prev_head_ea):
    return True

  return False

_POSSIBLE_REFS = set()
_REFS = {}
_HAS_NO_REFS = set()
_NO_REFS = tuple()
_ENABLE_CACHING = False

# Try to recognize an operand as a reference candidate when a target fixup
# is not available.
def _get_ref_candidate(inst, op, all_refs):
  global _POSSIBLE_REFS, _ENABLE_CACHING

  ref = None
  addr_val = idc.BADADDR

  if idc.o_imm == op.type:
    addr_val = op.value
  elif op.type in (idc.o_displ, idc.o_mem, idc.o_near):
    addr_val = op.addr
  else:
    return None

  seg_ea = idc.SegStart(addr_val)
  if is_invalid_ea(seg_ea):
    return None

  if addr_val not in all_refs and is_head(addr_val):
    all_refs.add(addr_val)

  # Some other instruction/data references this thing. Let's assume it's
  # a real thing within this particular instruction.
  if addr_val not in all_refs and is_referenced(addr_val):
    all_refs.add(addr_val)

  # Curiously, sometimes `idaq` will recognize references that `idal64` will
  # not. It's possible that this is due to configuration options. This happened
  # in SQLite 3, where the `sqlite3_config` function references a field inside
  # of the `sqlite3Config` global structure variable. 
  if addr_val not in all_refs and _is_address_of_struct_field(addr_val):
    all_refs.add(addr_val)

  # Same as above, `idal64` can miss things that `idaq` gets.
  if addr_val not in all_refs and _is_near_another_head(addr_val, 128):
    DEBUG("WARNING: Adding reference from {:x} to {:x}, which is near other heads".format(
        inst.ea, addr_val))
    all_refs.add(addr_val)

  # # Same as above, `idal64` can miss things that `idaq` gets.
  # if addr_val not in all_refs and _try_create_array(addr_val):
  #   all_refs.add(addr_val)

  # The idea here is that if we have seen a possible ref show up more than once,
  # then lets assume it's actually a real reference. This sometimes happens
  # with strings, especially in SQLite3.
  if addr_val not in all_refs and addr_val in _POSSIBLE_REFS:
    all_refs.add(addr_val)
    DEBUG("Adding multiply seen {:x} as a reference target".format(addr_val))

  if addr_val not in all_refs:
    DEBUG("POSSIBLE ERROR: Not adding reference from {:x} to {:x}".format(
        inst.ea, addr_val))
    _POSSIBLE_REFS.add(addr_val)
    return None

  ref = Reference(addr_val, op.offb)

  # Make sure we add in a reference to the (possibly new) head, addressed
  # by `addr_val`.
  make_head(addr_val)
  idc.add_dref(inst.ea, addr_val, idc.XREF_USER)
  return ref

def memop_is_actually_displacement(inst):
  """IDA will unhelpfully decode something like `jmp ds:off_48A5F0[rax*8]`
  and tell us that this is an `o_mem` rather than an `o_displ`. We really want
  to recognize it as an `o_displ` because the memory reference is a displacement
  and not an absolute address."""
  asm = idc.GetDisasm(inst.ea)
  return "[" in asm and ("+" in asm or "*" in asm)

# Return the set of all references from `ea` to anything.
def get_all_references_from(ea):
  all_refs = set()
  for ref_ea in idautils.DataRefsFrom(ea):
    if not is_invalid_ea(ref_ea):
      all_refs.add(ref_ea)

  for ref_ea in idautils.CodeRefsFrom(ea, 0):
    if not is_invalid_ea(ref_ea):
      all_refs.add(ref_ea)

  for ref_ea in idautils.CodeRefsFrom(ea, 1):
    if not is_invalid_ea(ref_ea):
      all_refs.add(ref_ea)

  return all_refs

# This is a real hack. It can take a few tries to really find references, so
# we'll only enable reference caching after we do some processing of segments.
# Hopefully after such processing, we will have discovered item heads that IDA
# hadn't previously identified. Curiosly, `idaq` will sometimes recognize
# references or item heads that `idal64` does not.
def enable_reference_caching():
  global _ENABLE_CACHING
  _ENABLE_CACHING = True

# Get a list of references from an instruction.
def get_instruction_references(arg, binary_is_pie=False):
  global _ENABLE_CACHING

  inst = arg
  if isinstance(arg, (int, long)):
    inst, _ = decode_instruction(arg)
  
  if not inst:
    return _NO_REFS

  if _ENABLE_CACHING:
    if inst.ea in _HAS_NO_REFS:
      return _NO_REFS

    if inst.ea in _REFS:
      return _REFS[inst.ea]

  offset_to_ref = {}
  all_refs = get_all_references_from(inst.ea)
  for ea in xrange(inst.ea, inst.ea + inst.size):
    targ_ea = idc.GetFixupTgtOff(ea)
    if not is_invalid_ea(targ_ea):
      all_refs.add(targ_ea)
      ref = Reference(targ_ea, ea - inst.ea)
      offset_to_ref[ref.offset] = ref

  refs = []
  for i, op in enumerate(inst.Operands):
    if not op.type:
      continue

    op_ea = inst.ea + op.offb
    if op.offb in offset_to_ref:
      ref = offset_to_ref[op.offb]
    else:
      ref = _get_ref_candidate(inst, op, all_refs)

    if not ref or not idc.GetFlags(ref.ea):
      continue

    # Immediate constant, may be the absolute address of a data reference.
    if idc.o_imm == op.type:
      seg_begin = idaapi.getseg(ref.ea)
      seg_end = idaapi.getseg(ref.ea + idc.ItemSize(ref.ea) - 1)

      # If the immediate constant is not within a segment, or crosses
      # two segments then don't treat it as a reference.
      if not seg_begin or not seg_end or seg_begin.startEA != seg_end.startEA:
        idaapi.del_dref(op_ea, op.value)
        idaapi.del_cref(op_ea, op.value, False)
        continue

      # If this is a PIE-mode, 64-bit binary, then most likely the immediate
      # operand is not a data ref. 
      if seg_begin.use64() and binary_is_pie:
        idaapi.del_dref(op_ea, op.value)
        idaapi.del_cref(op_ea, op.value, False)
        continue

      ref.type = Reference.IMMEDIATE
      ref.symbol = get_symbol_name(op_ea, ref.ea)

    # Displacement within a memory operand, excluding PC-relative
    # displacements when those are memory references.
    elif idc.o_displ == op.type:
      assert ref.ea == op.addr
      ref.type = Reference.DISPLACEMENT
      ref.symbol = get_symbol_name(op_ea, ref.ea)

    # Absolute memory reference, and PC-relative memory reference. These
    # are references that IDA can recognize statically.
    elif idc.o_mem == op.type:
      assert ref.ea == op.addr
      if memop_is_actually_displacement(inst):
        ref.type = Reference.DISPLACEMENT
      else:
        ref.type = Reference.MEMORY
      ref.symbol = get_symbol_name(op_ea, ref.ea)

    # Code reference.
    elif idc.o_near == op.type:
      assert ref.ea == op.addr
      ref.type = Reference.CODE
      ref.symbol = get_symbol_name(op_ea, ref.ea)

    # TODO(pag): Not sure what to do with this yet.
    elif idc.o_far == op.type:
      DEBUG("ERROR inst={:x}\ntarget={:x}\nsym={}".format(
          inst.ea, ref.ea, get_symbol_name(op_ea, ref.ea)))
      assert False

    refs.append(ref)

  for ref in refs:
    assert not is_invalid_ea(ref.ea)

  if len(refs):
    refs = tuple(refs)
    if _ENABLE_CACHING:
      _REFS[inst.ea] = refs
    return refs
  else:
    if _ENABLE_CACHING:
      _HAS_NO_REFS.add(inst.ea)
    return _NO_REFS

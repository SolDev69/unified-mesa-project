/*
 * Copyright © 2022 Valve Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */
#include "helpers.h"

using namespace aco;

BEGIN_TEST(insert_waitcnt.ds_ordered_count)
   if (!setup_cs(NULL, GFX10_3))
      return;

   Operand def0(PhysReg(256), v1);
   Operand def1(PhysReg(257), v1);
   Operand def2(PhysReg(258), v1);
   Operand gds_base(PhysReg(259), v1);
   Operand chan_counter(PhysReg(260), v1);
   Operand m(m0, s1);

   Instruction* ds_instr;
   //>> ds_ordered_count %0:v[0], %0:v[3], %0:m0 offset0:3072 gds storage:gds semantics:volatile
   //! s_waitcnt lgkmcnt(0)
   ds_instr = bld.ds(aco_opcode::ds_ordered_count, def0, gds_base, m, 3072u, 0u, true);
   ds_instr->ds().sync = memory_sync_info(storage_gds, semantic_volatile);

   //! ds_add_rtn_u32 %0:v[1], %0:v[3], %0:v[4], %0:m0 gds storage:gds semantics:volatile,atomic,rmw
   ds_instr = bld.ds(aco_opcode::ds_add_rtn_u32, def1, gds_base, chan_counter, m, 0u, 0u, true);
   ds_instr->ds().sync = memory_sync_info(storage_gds, semantic_atomicrmw);

   //! s_waitcnt lgkmcnt(0)
   //! ds_ordered_count %0:v[2], %0:v[3], %0:m0 offset0:3840 gds storage:gds semantics:volatile
   ds_instr = bld.ds(aco_opcode::ds_ordered_count, def2, gds_base, m, 3840u, 0u, true);
   ds_instr->ds().sync = memory_sync_info(storage_gds, semantic_volatile);

   finish_waitcnt_test();
END_TEST

BEGIN_TEST(insert_waitcnt.waw.mixed_vmem_lds.vmem)
   if (!setup_cs(NULL, GFX10))
      return;

   Definition def_v4(PhysReg(260), v1);
   Operand op_v0(PhysReg(256), v1);
   Operand desc0(PhysReg(0), s4);

   //>> BB0
   //! /* logical preds: / linear preds: / kind: top-level, */
   //! v1: %0:v[4] = buffer_load_dword %0:s[0-3], %0:v[0], 0
   bld.mubuf(aco_opcode::buffer_load_dword, def_v4, desc0, op_v0, Operand::zero(), 0, false);

   //>> BB1
   //! /* logical preds: / linear preds: / kind: */
   //! v1: %0:v[4] = ds_read_b32 %0:v[0]
   bld.reset(program->create_and_insert_block());
   bld.ds(aco_opcode::ds_read_b32, def_v4, op_v0);

   bld.reset(program->create_and_insert_block());
   program->blocks[2].linear_preds.push_back(0);
   program->blocks[2].linear_preds.push_back(1);
   program->blocks[2].logical_preds.push_back(0);
   program->blocks[2].logical_preds.push_back(1);

   //>> BB2
   //! /* logical preds: BB0, BB1, / linear preds: BB0, BB1, / kind: uniform, */
   //! s_waitcnt lgkmcnt(0)
   //! v1: %0:v[4] = buffer_load_dword %0:s[0-3], %0:v[0], 0
   bld.mubuf(aco_opcode::buffer_load_dword, def_v4, desc0, op_v0, Operand::zero(), 0, false);

   finish_waitcnt_test();
END_TEST

BEGIN_TEST(insert_waitcnt.waw.mixed_vmem_lds.lds)
   if (!setup_cs(NULL, GFX10))
      return;

   Definition def_v4(PhysReg(260), v1);
   Operand op_v0(PhysReg(256), v1);
   Operand desc0(PhysReg(0), s4);

   //>> BB0
   //! /* logical preds: / linear preds: / kind: top-level, */
   //! v1: %0:v[4] = buffer_load_dword %0:s[0-3], %0:v[0], 0
   bld.mubuf(aco_opcode::buffer_load_dword, def_v4, desc0, op_v0, Operand::zero(), 0, false);

   //>> BB1
   //! /* logical preds: / linear preds: / kind: */
   //! v1: %0:v[4] = ds_read_b32 %0:v[0]
   bld.reset(program->create_and_insert_block());
   bld.ds(aco_opcode::ds_read_b32, def_v4, op_v0);

   bld.reset(program->create_and_insert_block());
   program->blocks[2].linear_preds.push_back(0);
   program->blocks[2].linear_preds.push_back(1);
   program->blocks[2].logical_preds.push_back(0);
   program->blocks[2].logical_preds.push_back(1);

   //>> BB2
   //! /* logical preds: BB0, BB1, / linear preds: BB0, BB1, / kind: uniform, */
   //! s_waitcnt vmcnt(0)
   //! v1: %0:v[4] = ds_read_b32 %0:v[0]
   bld.ds(aco_opcode::ds_read_b32, def_v4, op_v0);

   finish_waitcnt_test();
END_TEST

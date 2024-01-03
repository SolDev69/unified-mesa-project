/*
 * Copyright (C) 2022 Collabora Ltd.
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
 */

#pragma once

#include "gen_macros.h"

/*
 * ceu_builder implements a builder for CSF command queues. It manages the
 * allocation and overflow behaviour of queues and provides helpers for emitting
 * commands to run on the CEU.
 *
 * Users must implement the ceu_alloc_queue method performing the physical
 * memory allocation and queue binding. Users must initialize a queue with
 * ceu_builder_init.
 */

struct ceu_queue {
   /* CPU pointer */
   uint64_t *cpu;

   /* GPU pointer */
   uint64_t gpu;

   /* Capacity */
   size_t capacity;
};

struct ceu_builder_conf {
   /* Number of 32-bit registers in the hardware register file */
   uint8_t nr_registers;

   /* Number of 32-bit registers used by the kernel at submission time */
   uint8_t nr_kernel_registers;

   /* CS chunk allocator. */
   struct ceu_queue (*alloc)(void *cookie);

   /* Cookie passed back to ceu_alloc_queue for caller use */
   void *cookie;
};

typedef struct ceu_builder {
   /* CEU builder configuration */
   struct ceu_builder_conf conf;

   /* Initial (root) queue */
   struct ceu_queue root;

   /* Number of instructions emitted into the root queue */
   uint32_t root_size;

   /* Current queue */
   struct ceu_queue queue;

   /* Number of instructions emitted into the current queue so far */
   uint32_t queue_size;

   /* Move immediate instruction at the end of the last queue that needs to
    * be patched with the final length of the current queue in order to
    * facilitate correct overflow behaviour.
    */
   uint32_t *length_patch;
} ceu_builder;

static void
ceu_builder_init(struct ceu_builder *b, const struct ceu_builder_conf *conf,
                 struct ceu_queue root)
{
   *b = (struct ceu_builder){
      .conf = *conf,
      .queue = root,
      .root = root,
   };
}

/*
 * Wrap the current queue. External users shouldn't call this function
 * directly, they should call ceu_finish() when they are done building
 * the command stream, which will in turn call ceu_wrap_queue().
 *
 * Internally, this is also used to finalize internal subqueues when
 * allocating new subqueues. See ceu_alloc for details.
 *
 * This notably requires patching the previous queue with the length
 * we ended up emitting for this queue.
 */
static void
ceu_wrap_queue(ceu_builder *b)
{
   if (b->length_patch) {
      *b->length_patch = (b->queue_size * 8);
      b->length_patch = NULL;
   }

   if (b->root.gpu == b->queue.gpu)
      b->root_size = b->queue_size;
}

/* Call this when you are done building a command stream and want to prepare
 * it for submission.
 */
static unsigned
ceu_finish(ceu_builder *b)
{
   ceu_wrap_queue(b);
   return b->root_size;
}

#if PAN_ARCH >= 10
enum ceu_index_type { CEU_INDEX_REGISTER = 0, CEU_INDEX_IMMEDIATE = 1 };

typedef struct ceu_index {
   enum ceu_index_type type;

   /* Number of 32-bit words in the index, must be nonzero */
   uint8_t size;

   union {
      uint64_t imm;
      uint8_t reg;
   };
} ceu_index;

static uint8_t
ceu_to_reg_tuple(ceu_index idx, ASSERTED uint8_t expected_size)
{
   assert(idx.type == CEU_INDEX_REGISTER);
   assert(idx.size == expected_size);

   return idx.reg;
}

static uint8_t
ceu_to_reg32(ceu_index idx)
{
   return ceu_to_reg_tuple(idx, 1);
}

static uint8_t
ceu_to_reg64(ceu_index idx)
{
   return ceu_to_reg_tuple(idx, 2);
}

static ceu_index
ceu_reg_tuple(ASSERTED ceu_builder *b, uint8_t reg, uint8_t size)
{
   assert(reg + size <= b->conf.nr_registers && "overflowed register file");
   assert(size < 16 && "unsupported");

   return (
      struct ceu_index){.type = CEU_INDEX_REGISTER, .size = size, .reg = reg};
}

static inline ceu_index
ceu_reg32(ceu_builder *b, uint8_t reg)
{
   return ceu_reg_tuple(b, reg, 1);
}

static inline ceu_index
ceu_reg64(ceu_builder *b, uint8_t reg)
{
   assert((reg % 2) == 0 && "unaligned 64-bit reg");
   return ceu_reg_tuple(b, reg, 2);
}

/*
 * The top of the register file is reserved for ceu_builder internal use. We
 * need 3 spare registers for handling command queue overflow. These are
 * available here.
 */
static inline ceu_index
ceu_overflow_address(ceu_builder *b)
{
   return ceu_reg64(b, b->conf.nr_registers - 2);
}

static inline ceu_index
ceu_overflow_length(ceu_builder *b)
{
   return ceu_reg32(b, b->conf.nr_registers - 3);
}

static ceu_index
ceu_extract32(ceu_builder *b, ceu_index idx, uint8_t word)
{
   assert(idx.type == CEU_INDEX_REGISTER && "unsupported");
   assert(word < idx.size && "overrun");

   return ceu_reg32(b, idx.reg + word);
}

static inline void *
ceu_alloc(ceu_builder *b)
{
   /* If the current command queue runs out of space, allocate a new one
    * and jump to it. We actually do this a few instructions before running
    * out, because the sequence to jump to a new queue takes multiple
    * instructions.
    */
   if (unlikely((b->queue_size + 4) > b->queue.capacity)) {
      /* Now, allocate a new queue */
      struct ceu_queue newq = b->conf.alloc(b->conf.cookie);

      uint64_t *ptr = b->queue.cpu + (b->queue_size++);

      pan_pack(ptr, CEU_MOVE, I) {
         I.destination = ceu_to_reg64(ceu_overflow_address(b));
         I.immediate = newq.gpu;
      }

      ptr = b->queue.cpu + (b->queue_size++);

      pan_pack(ptr, CEU_MOVE32, I) {
         I.destination = ceu_to_reg32(ceu_overflow_length(b));
      }

      /* The length will be patched in later */
      uint32_t *length_patch = (uint32_t *)ptr;

      ptr = b->queue.cpu + (b->queue_size++);

      pan_pack(ptr, CEU_JUMP, I) {
         I.length = ceu_to_reg32(ceu_overflow_length(b));
         I.address = ceu_to_reg64(ceu_overflow_address(b));
      }

      /* Now that we've emitted everything, finish up the previous queue */
      ceu_wrap_queue(b);

      /* And make this one current */
      b->length_patch = length_patch;
      b->queue = newq;
      b->queue_size = 0;
   }

   assert(b->queue_size < b->queue.capacity);
   return b->queue.cpu + (b->queue_size++);
}

/*
 * Helper to emit a new instruction into the command queue. The allocation needs
 * to be separated out being pan_pack can evaluate its argument multiple times,
 * yet ceu_alloc has side effects.
 */
#define ceu_emit(b, T, cfg)                                                    \
   void *_dest = ceu_alloc(b);                                                 \
   pan_pack(_dest, CEU_##T, cfg)

static inline void
ceu_move32_to(ceu_builder *b, ceu_index dest, uint32_t imm)
{
   ceu_emit(b, MOVE32, I) {
      I.destination = ceu_to_reg32(dest);
      I.immediate = imm;
   }
}

static inline void
ceu_move48_to(ceu_builder *b, ceu_index dest, uint64_t imm)
{
   ceu_emit(b, MOVE, I) {
      I.destination = ceu_to_reg64(dest);
      I.immediate = imm;
   }
}

static inline void
ceu_wait_slots(ceu_builder *b, uint8_t slots)
{
   ceu_emit(b, WAIT, I) {
      I.slots = slots;
   }
}

static inline void
ceu_branch(ceu_builder *b, int16_t offset, enum mali_ceu_condition cond,
           ceu_index val)
{
   ceu_emit(b, BRANCH, I) {
      I.offset = offset;
      I.condition = cond;
      I.value = ceu_to_reg32(val);
   }
}

static inline void
ceu_run_compute(ceu_builder *b, unsigned task_increment,
                enum mali_task_axis task_axis)
{
   ceu_emit(b, RUN_COMPUTE, I) {
      I.task_increment = task_increment;
      I.task_axis = task_axis;

      /* We always use the first table for compute jobs */
   }
}

static inline void
ceu_run_idvs(ceu_builder *b, enum mali_draw_mode draw_mode,
             enum mali_index_type index_type, bool secondary_shader)
{
   ceu_emit(b, RUN_IDVS, I) {
      /* We do not have a use case for traditional IDVS */
      I.malloc_enable = true;

      /* We hardcode these settings for now, we can revisit this if we
       * rework how we emit state later.
       */
      I.fragment_srt_select = true;

      /* Pack the override we use */
      pan_pack(&I.flags_override, PRIMITIVE_FLAGS, cfg) {
         cfg.draw_mode = draw_mode;
         cfg.index_type = index_type;
         cfg.secondary_shader = secondary_shader;
      }
   }
}

static inline void
ceu_run_fragment(ceu_builder *b, bool enable_tem)
{
   ceu_emit(b, RUN_FRAGMENT, I) {
      I.enable_tem = enable_tem;
   }
}

static inline void
ceu_finish_tiling(ceu_builder *b)
{
   ceu_emit(b, FINISH_TILING, _)
      ;
}

static inline void
ceu_finish_fragment(ceu_builder *b, bool increment_frag_completed,
                    ceu_index first_free_heap_chunk,
                    ceu_index last_free_heap_chunk, uint16_t scoreboard_mask,
                    uint8_t signal_slot)
{
   ceu_emit(b, FINISH_FRAGMENT, I) {
      I.increment_fragment_completed = increment_frag_completed;
      I.wait_mask = scoreboard_mask;
      I.first_heap_chunk = ceu_to_reg64(first_free_heap_chunk);
      I.last_heap_chunk = ceu_to_reg64(last_free_heap_chunk);
      I.scoreboard_entry = signal_slot;
   }
}

static inline void
ceu_heap_set(ceu_builder *b, ceu_index address)
{
   ceu_emit(b, HEAP_SET, I) {
      I.address = ceu_to_reg64(address);
   }
}

static inline void
ceu_load_to(ceu_builder *b, ceu_index dest, ceu_index address, uint16_t mask,
            int16_t offset)
{
   ceu_emit(b, LOAD_MULTIPLE, I) {
      I.base = ceu_to_reg_tuple(dest, util_bitcount(mask));
      I.address = ceu_to_reg64(address);
      I.mask = mask;
      I.offset = offset;
   }
}

static inline void
ceu_store(ceu_builder *b, ceu_index data, ceu_index address, uint16_t mask,
          int16_t offset)
{
   ceu_emit(b, STORE_MULTIPLE, I) {
      I.base = ceu_to_reg_tuple(data, util_bitcount(mask));
      I.address = ceu_to_reg64(address);
      I.mask = mask;
      I.offset = offset;
   }
}

/*
 * Select which scoreboard entry will track endpoint tasks and other tasks
 * respectively. Pass to ceu_wait to wait later.
 */
static inline void
ceu_set_scoreboard_entry(ceu_builder *b, uint8_t ep, uint8_t other)
{
   assert(ep < 8 && "invalid slot");
   assert(other < 8 && "invalid slot");

   ceu_emit(b, SET_SB_ENTRY, I) {
      I.endpoint_entry = ep;
      I.other_entry = other;
   }
}

static inline void
ceu_require_all(ceu_builder *b)
{
   ceu_emit(b, REQ_RESOURCE, I) {
      I.compute = true;
      I.tiler = true;
      I.idvs = true;
      I.fragment = true;
   }
}

static inline void
ceu_require_compute(ceu_builder *b)
{
   ceu_emit(b, REQ_RESOURCE, I)
      I.compute = true;
}

static inline void
ceu_require_fragment(ceu_builder *b)
{
   ceu_emit(b, REQ_RESOURCE, I)
      I.fragment = true;
}

static inline void
ceu_require_idvs(ceu_builder *b)
{
   ceu_emit(b, REQ_RESOURCE, I) {
      I.compute = true;
      I.tiler = true;
      I.idvs = true;
   }
}

static inline void
ceu_heap_operation(ceu_builder *b, enum mali_ceu_heap_operation operation)
{
   ceu_emit(b, HEAP_OPERATION, I)
      I.operation = operation;
}

static inline void
ceu_vt_start(ceu_builder *b)
{
   ceu_heap_operation(b, MALI_CEU_HEAP_OPERATION_VERTEX_TILER_STARTED);
}

static inline void
ceu_vt_end(ceu_builder *b)
{
   ceu_heap_operation(b, MALI_CEU_HEAP_OPERATION_VERTEX_TILER_COMPLETED);
}

static inline void
ceu_frag_end(ceu_builder *b)
{
   ceu_heap_operation(b, MALI_CEU_HEAP_OPERATION_FRAGMENT_COMPLETED);
}

static inline void
ceu_flush_caches(ceu_builder *b, enum mali_ceu_flush_mode l2,
                 enum mali_ceu_flush_mode lsc, bool other_inv,
                 ceu_index flush_id, uint16_t scoreboard_mask,
                 uint8_t signal_slot)
{
   ceu_emit(b, FLUSH_CACHE2, I) {
      I.l2_flush_mode = l2;
      I.lsc_flush_mode = lsc;
      I.other_invalidate = other_inv;
      I.scoreboard_mask = scoreboard_mask;
      I.latest_flush_id = ceu_to_reg32(flush_id);
      I.scoreboard_entry = signal_slot;
   }
}

/* Pseudoinstructions follow */

static inline void
ceu_move64_to(ceu_builder *b, ceu_index dest, uint64_t imm)
{
   if (imm < (1ull << 48)) {
      /* Zero extends */
      ceu_move48_to(b, dest, imm);
   } else {
      ceu_move32_to(b, ceu_extract32(b, dest, 0), imm);
      ceu_move32_to(b, ceu_extract32(b, dest, 1), imm >> 32);
   }
}

static inline void
ceu_load32_to(ceu_builder *b, ceu_index dest, ceu_index address, int16_t offset)
{
   ceu_load_to(b, dest, address, BITFIELD_MASK(1), offset);
}

static inline void
ceu_load64_to(ceu_builder *b, ceu_index dest, ceu_index address, int16_t offset)
{
   ceu_load_to(b, dest, address, BITFIELD_MASK(2), offset);
}

static inline void
ceu_store32(ceu_builder *b, ceu_index data, ceu_index address, int16_t offset)
{
   ceu_store(b, data, address, BITFIELD_MASK(1), offset);
}

static inline void
ceu_store64(ceu_builder *b, ceu_index data, ceu_index address, int16_t offset)
{
   ceu_store(b, data, address, BITFIELD_MASK(2), offset);
}

static inline void
ceu_wait_slot(ceu_builder *b, uint8_t slot)
{
   assert(slot < 8 && "invalid slot");

   ceu_wait_slots(b, BITFIELD_BIT(slot));
}

static inline void
ceu_store_state(ceu_builder *b, uint8_t signal_slot, ceu_index address,
                enum mali_ceu_state state, uint16_t wait_mask, int16_t offset)
{
   ceu_emit(b, STORE_STATE, I) {
      I.offset = offset;
      I.wait_mask = wait_mask;
      I.state = state;
      I.address = ceu_to_reg64(address);
      I.scoreboard_slot = signal_slot;
   }
}

static inline void
ceu_add64(ceu_builder *b, ceu_index dest, ceu_index src, uint32_t imm)
{
   ceu_emit(b, ADD_IMMEDIATE64, I) {
      I.destination = ceu_to_reg64(dest);
      I.source = ceu_to_reg64(src);
      I.immediate = imm;
   }
}

static inline void
ceu_add32(ceu_builder *b, ceu_index dest, ceu_index src, uint32_t imm)
{
   ceu_emit(b, ADD_IMMEDIATE32, I) {
      I.destination = ceu_to_reg32(dest);
      I.source = ceu_to_reg32(src);
      I.immediate = imm;
   }
}

#endif /* PAN_ARCH >= 10 */

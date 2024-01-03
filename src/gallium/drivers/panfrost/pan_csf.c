/*
 * Copyright (C) 2023 Collabora Ltd.
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
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "decode.h"

#include "drm-uapi/panthor_drm.h"

#include "genxml/ceu_builder.h"

#include "pan_blitter.h"
#include "pan_cmdstream.h"
#include "pan_context.h"
#include "pan_csf.h"
#include "pan_job.h"

#if PAN_ARCH < 10
#error "CSF helpers are only used for gen >= 10"
#endif

static struct ceu_queue
csf_alloc_ceu_queue(void *cookie)
{
   assert(cookie && "Self-contained queues can't be extended.");

   struct panfrost_batch *batch = cookie;
   unsigned capacity = 4096;
   struct panfrost_bo *bo = panfrost_batch_create_bo(
      batch, capacity * 8, 0, PIPE_SHADER_VERTEX, "Command queue");

   memset(bo->ptr.cpu, 0xFF, capacity * 8);

   return (struct ceu_queue){
      .cpu = bo->ptr.cpu,
      .gpu = bo->ptr.gpu,
      .capacity = capacity,
   };
}

void
GENX(csf_cleanup_batch)(struct panfrost_batch *batch)
{
   free(batch->csf.cs.builder);
}

void
GENX(csf_init_batch)(struct panfrost_batch *batch)
{
   /* Allocate and bind the command queue */
   struct ceu_queue queue = csf_alloc_ceu_queue(batch);
   const struct ceu_builder_conf conf = {
      .nr_registers = 96,
      .nr_kernel_registers = 4,
      .alloc = csf_alloc_ceu_queue,
      .cookie = batch,
   };

   /* Setup the queue builder */
   batch->csf.cs.builder = malloc(sizeof(ceu_builder));
   ceu_builder_init(batch->csf.cs.builder, &conf, queue);
   ceu_require_all(batch->csf.cs.builder);

   /* Set up entries */
   ceu_builder *b = batch->csf.cs.builder;
   ceu_set_scoreboard_entry(b, 2, 0);

   /* Initialize the state vector */
   for (unsigned i = 0; i < 64; i += 2)
      ceu_move64_to(b, ceu_reg64(b, i), 0);

   batch->framebuffer = pan_pool_alloc_desc_aggregate(
      &batch->pool.base, PAN_DESC(FRAMEBUFFER), PAN_DESC(ZS_CRC_EXTENSION),
      PAN_DESC_ARRAY(MAX2(batch->key.nr_cbufs, 1), RENDER_TARGET));
   batch->tls = pan_pool_alloc_desc(&batch->pool.base, LOCAL_STORAGE);
}

static void
csf_prepare_qsubmit(struct panfrost_context *ctx,
                    struct drm_panthor_queue_submit *submit, uint8_t queue,
                    uint64_t cs_start, uint32_t cs_size,
                    struct drm_panthor_sync_op *syncs, uint32_t sync_count)
{
   struct panfrost_device *dev = pan_device(ctx->base.screen);

   *submit = (struct drm_panthor_queue_submit){
      .queue_index = queue,
      .stream_addr = cs_start,
      .stream_size = cs_size,
      .latest_flush = panthor_kmod_get_flush_id(dev->kmod.dev),
      .syncs = DRM_PANTHOR_OBJ_ARRAY(sync_count, syncs),
   };
}

static void
csf_prepare_gsubmit(struct panfrost_context *ctx,
                    struct drm_panthor_group_submit *gsubmit,
                    struct drm_panthor_queue_submit *qsubmits,
                    uint32_t qsubmit_count)
{
   *gsubmit = (struct drm_panthor_group_submit){
      .group_handle = ctx->csf.group_handle,
      .queue_submits = DRM_PANTHOR_OBJ_ARRAY(qsubmit_count, qsubmits),
   };
}

static int
csf_submit_gsubmit(struct panfrost_context *ctx,
                   struct drm_panthor_group_submit *gsubmit)
{
   struct panfrost_device *dev = pan_device(ctx->base.screen);
   int ret = 0;

   if (!ctx->is_noop) {
      ret = drmIoctl(panfrost_device_fd(dev), DRM_IOCTL_PANTHOR_GROUP_SUBMIT,
                     gsubmit);
   }

   if (ret)
      return errno;

   if (dev->debug & (PAN_DBG_TRACE | PAN_DBG_SYNC)) {
      /* Wait so we can get errors reported back */
      drmSyncobjWait(panfrost_device_fd(dev), &ctx->syncobj, 1, INT64_MAX, 0,
                     NULL);

      if ((dev->debug & PAN_DBG_TRACE) && dev->arch >= 10) {
         const struct drm_panthor_queue_submit *qsubmits =
            (void *)(uintptr_t)gsubmit->queue_submits.array;

         for (unsigned i = 0; i < gsubmit->queue_submits.count; i++) {
            uint32_t regs[256] = {0};
            pandecode_cs(dev->decode_ctx, qsubmits[i].stream_addr,
                         qsubmits[i].stream_size, panfrost_device_gpu_id(dev),
                         regs);
         }
      }

      if (dev->debug & PAN_DBG_DUMP)
         pandecode_dump_mappings(dev->decode_ctx);
   }

   return 0;
}

static void
csf_emit_batch_end(struct panfrost_batch *batch)
{
   ceu_builder *b = batch->csf.cs.builder;

   /* Barrier to let everything finish */
   ceu_wait_slots(b, BITFIELD_MASK(8));

   /* Get the CS state */
   batch->csf.cs.state = pan_pool_alloc_aligned(&batch->pool.base, 8, 8);
   memset(batch->csf.cs.state.cpu, ~0, 8);
   ceu_move64_to(b, ceu_reg64(b, 90), batch->csf.cs.state.gpu);
   ceu_store_state(b, 0, ceu_reg64(b, 90), MALI_CEU_STATE_ERROR_STATUS, 0, 0);

   /* Flush caches now that we're done (synchronous) */
   ceu_index flush_id = ceu_reg32(b, 74);
   ceu_move32_to(b, flush_id, 0);
   ceu_flush_caches(b, MALI_CEU_FLUSH_MODE_CLEAN_AND_INVALIDATE,
                    MALI_CEU_FLUSH_MODE_CLEAN_AND_INVALIDATE, true, flush_id, 0,
                    0);

   /* Finish the command stream */
   ceu_finish(batch->csf.cs.builder);
}

int
GENX(csf_submit_batch)(struct panfrost_batch *batch)
{
   /* Close the batch before submitting. */
   csf_emit_batch_end(batch);

   uint32_t cs_instr_count = batch->csf.cs.builder->root_size;
   uint64_t cs_start = batch->csf.cs.builder->root.gpu;
   uint32_t cs_size = cs_instr_count * 8;
   uint64_t vm_sync_signal_point, vm_sync_wait_point = 0, bo_sync_point;
   struct panfrost_context *ctx = batch->ctx;
   struct panfrost_device *dev = pan_device(ctx->base.screen);
   uint32_t vm_sync_handle, bo_sync_handle, sync_count = 0;
   struct drm_panthor_sync_op *syncs = NULL;
   int ret;

   panthor_kmod_vm_new_sync_point(dev->kmod.vm, &vm_sync_handle,
                                  &vm_sync_signal_point);
   assert(vm_sync_handle > 0 && vm_sync_signal_point > 0);

   syncs = calloc(batch->num_bos + 5, sizeof(*syncs));
   assert(syncs);

   util_dynarray_foreach(&batch->bos, pan_bo_access, ptr) {
      unsigned i = ptr - util_dynarray_element(&batch->bos, pan_bo_access, 0);
      pan_bo_access flags = *ptr;

      if (!flags)
         continue;

      /* Update the BO access flags so that panfrost_bo_wait() knows
       * about all pending accesses.
       * We only keep the READ/WRITE info since this is all the BO
       * wait logic cares about.
       * We also preserve existing flags as this batch might not
       * be the first one to access the BO.
       */
      struct panfrost_bo *bo = pan_lookup_bo(dev, i);

      bo->gpu_access |= flags & (PAN_BO_ACCESS_RW);

      ret = panthor_kmod_bo_get_sync_point(bo->kmod_bo, &bo_sync_handle,
                                           &bo_sync_point,
                                           !(flags & PAN_BO_ACCESS_WRITE));
      if (ret)
         goto out_free_syncs;

      if (bo_sync_handle == vm_sync_handle) {
         vm_sync_wait_point = MAX2(vm_sync_wait_point, bo_sync_point);
      } else {
         assert(bo_sync_point == 0 || !bo->kmod_bo->exclusive_vm);
         syncs[sync_count++] = (struct drm_panthor_sync_op){
            .flags =
               DRM_PANTHOR_SYNC_OP_WAIT |
               (bo_sync_point ? DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_TIMELINE_SYNCOBJ
                              : DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_SYNCOBJ),
            .handle = bo_sync_handle,
            .timeline_value = bo_sync_point,
         };
      }
   }

   util_dynarray_foreach(&batch->pool.bos, struct panfrost_bo *, bo) {
      (*bo)->gpu_access |= PAN_BO_ACCESS_RW;

      ret = panthor_kmod_bo_get_sync_point((*bo)->kmod_bo, &bo_sync_handle,
                                           &bo_sync_point, false);
      if (ret)
         goto out_free_syncs;

      assert(bo_sync_handle == vm_sync_handle);
      vm_sync_wait_point = MAX2(vm_sync_wait_point, bo_sync_point);
   }

   util_dynarray_foreach(&batch->invisible_pool.bos, struct panfrost_bo *, bo) {
      (*bo)->gpu_access |= PAN_BO_ACCESS_RW;

      ret = panthor_kmod_bo_get_sync_point((*bo)->kmod_bo, &bo_sync_handle,
                                           &bo_sync_point, false);
      if (ret)
         goto out_free_syncs;

      assert(bo_sync_handle == vm_sync_handle);
      vm_sync_wait_point = MAX2(vm_sync_wait_point, bo_sync_point);
   }

   /* Always used on Bifrost, occassionally used on Midgard */
   panthor_kmod_bo_get_sync_point(dev->sample_positions->kmod_bo,
                                  &bo_sync_handle, &bo_sync_point, true);
   dev->sample_positions->gpu_access |= PAN_BO_ACCESS_READ;
   vm_sync_wait_point = MAX2(vm_sync_wait_point, bo_sync_point);

   if (vm_sync_wait_point > 0) {
      syncs[sync_count++] = (struct drm_panthor_sync_op){
         .flags = DRM_PANTHOR_SYNC_OP_WAIT |
                  DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_TIMELINE_SYNCOBJ,
         .handle = vm_sync_handle,
         .timeline_value = vm_sync_wait_point,
      };
   }

   syncs[sync_count++] = (struct drm_panthor_sync_op){
      .flags = DRM_PANTHOR_SYNC_OP_SIGNAL |
               DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_TIMELINE_SYNCOBJ,
      .handle = vm_sync_handle,
      .timeline_value = vm_sync_signal_point,
   };

   syncs[sync_count++] = (struct drm_panthor_sync_op){
      .flags =
         DRM_PANTHOR_SYNC_OP_SIGNAL | DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_SYNCOBJ,
      .handle = ctx->syncobj,
   };

   if (ctx->in_sync_fd >= 0) {
      ret = drmSyncobjImportSyncFile(panfrost_device_fd(dev), ctx->in_sync_obj,
                                     ctx->in_sync_fd);
      assert(!ret);

      syncs[sync_count++] = (struct drm_panthor_sync_op){
         .flags =
            DRM_PANTHOR_SYNC_OP_WAIT | DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_SYNCOBJ,
         .handle = ctx->in_sync_obj,
      };
      close(ctx->in_sync_fd);
      ctx->in_sync_fd = -1;
   }

   struct drm_panthor_queue_submit qsubmit;
   struct drm_panthor_group_submit gsubmit;

   csf_prepare_qsubmit(ctx, &qsubmit, 0, cs_start, cs_size, syncs, sync_count);
   csf_prepare_gsubmit(ctx, &gsubmit, &qsubmit, 1);
   ret = csf_submit_gsubmit(ctx, &gsubmit);
   if (!ret) {
      util_dynarray_foreach(&batch->bos, pan_bo_access, ptr) {
         unsigned i =
            ptr - util_dynarray_element(&batch->bos, pan_bo_access, 0);
         pan_bo_access flags = *ptr;

         if (!flags)
            continue;

         struct panfrost_bo *bo = pan_lookup_bo(dev, i);

         ret = panthor_kmod_bo_attach_sync_point(
            bo->kmod_bo, vm_sync_handle, vm_sync_signal_point,
            !(flags & PAN_BO_ACCESS_WRITE));
         if (ret)
            goto out_free_syncs;
      }

      util_dynarray_foreach(&batch->pool.bos, struct panfrost_bo *, bo) {
         ret = panthor_kmod_bo_attach_sync_point((*bo)->kmod_bo, vm_sync_handle,
                                                 vm_sync_signal_point, false);
         if (ret)
            goto out_free_syncs;
      }

      util_dynarray_foreach(&batch->invisible_pool.bos, struct panfrost_bo *,
                            bo) {
         ret = panthor_kmod_bo_attach_sync_point((*bo)->kmod_bo, vm_sync_handle,
                                                 vm_sync_signal_point, false);
         if (ret)
            goto out_free_syncs;
      }

      ret = panthor_kmod_bo_attach_sync_point(dev->sample_positions->kmod_bo,
                                              vm_sync_handle,
                                              vm_sync_signal_point, true);
      if (ret)
         goto out_free_syncs;
   } else {
      struct drm_panthor_group_get_state state = {
         .group_handle = ctx->csf.group_handle,
      };

      ret = drmIoctl(panfrost_device_fd(dev), DRM_IOCTL_PANTHOR_GROUP_GET_STATE,
                     &state);
      if (ret) {
         mesa_loge("DRM_IOCTL_PANTHOR_GROUP_GET_STATE failed (err=%d)", errno);
         goto out_free_syncs;
      }

      if (state.state != 0)
         panfrost_context_reinit(ctx);
   }

   if (ret)
      goto out_free_syncs;

   /* Jobs won't be complete if blackhole rendering, that's ok */
   if (!ctx->is_noop && (dev->debug & PAN_DBG_SYNC) &&
       *((uint64_t *)batch->csf.cs.state.cpu) != 0) {
      fprintf(stderr, "Incomplete job or timeout\n");
      fflush(NULL);
      abort();
   }

out_free_syncs:
   free(syncs);
   return ret;
}

void
GENX(csf_preload_fb)(struct panfrost_batch *batch, struct pan_fb_info *fb)
{
   GENX(pan_preload_fb)
   (&batch->pool.base, NULL, fb, batch->tls.gpu, batch->tiler_ctx.bifrost,
    NULL);
}

void
GENX(csf_emit_fragment_job)(struct panfrost_batch *batch,
                            const struct pan_fb_info *pfb)
{
   ceu_builder *b = batch->csf.cs.builder;

   if (batch->draw_count > 0) {
      /* Finish tiling and wait for IDVS and tiling */
      ceu_finish_tiling(b);
      ceu_wait_slot(b, 2);
      ceu_vt_end(b);
   }

   /* Set up the fragment job */
   ceu_move64_to(b, ceu_reg64(b, 40), batch->framebuffer.gpu);
   ceu_move32_to(b, ceu_reg32(b, 42), (batch->miny << 16) | batch->minx);
   ceu_move32_to(b, ceu_reg32(b, 43),
                 ((batch->maxy - 1) << 16) | (batch->maxx - 1));

   /* Run the fragment job and wait */
   ceu_run_fragment(b, false);
   ceu_wait_slot(b, 2);

   /* Gather freed heap chunks and add them to the heap context free list
    * so they can be re-used next time the tiler heap runs out of chunks.
    * That's what ceu_finish_fragment() is all about. The list of freed
    * chunks is in the tiler context descriptor
    * (completed_{top,bottom fields}). */
   if (batch->tiler_ctx.bifrost) {
      ceu_move64_to(b, ceu_reg64(b, 94), batch->tiler_ctx.bifrost);
      ceu_load_to(b, ceu_reg_tuple(b, 90, 4), ceu_reg64(b, 94),
                  BITFIELD_MASK(4), 40);
      ceu_wait_slot(b, 0);
      ceu_finish_fragment(b, true, ceu_reg64(b, 90), ceu_reg64(b, 92), 0x0, 1);
      ceu_wait_slot(b, 1);
   }
}

static void
csf_emit_shader_regs(struct panfrost_batch *batch, enum pipe_shader_type stage,
                     mali_ptr shader)
{
   mali_ptr resources = panfrost_emit_resources(batch, stage);

   assert(stage == PIPE_SHADER_VERTEX || stage == PIPE_SHADER_FRAGMENT ||
          stage == PIPE_SHADER_COMPUTE);

   unsigned offset = (stage == PIPE_SHADER_FRAGMENT) ? 4 : 0;
   unsigned fau_count = DIV_ROUND_UP(batch->nr_push_uniforms[stage], 2);

   ceu_builder *b = batch->csf.cs.builder;
   ceu_move64_to(b, ceu_reg64(b, 0 + offset), resources);
   ceu_move64_to(b, ceu_reg64(b, 8 + offset),
                 batch->push_uniforms[stage] | ((uint64_t)fau_count << 56));
   ceu_move64_to(b, ceu_reg64(b, 16 + offset), shader);
}

void
GENX(csf_launch_grid)(struct panfrost_batch *batch,
                      const struct pipe_grid_info *info)
{
   /* Empty compute programs are invalid and don't make sense */
   if (batch->rsd[PIPE_SHADER_COMPUTE] == 0)
      return;

   struct panfrost_context *ctx = batch->ctx;
   struct panfrost_compiled_shader *cs = ctx->prog[PIPE_SHADER_COMPUTE];
   ceu_builder *b = batch->csf.cs.builder;

   csf_emit_shader_regs(batch, PIPE_SHADER_COMPUTE,
                        batch->rsd[PIPE_SHADER_COMPUTE]);

   ceu_move64_to(b, ceu_reg64(b, 24), batch->tls.gpu);

   /* Global attribute offset */
   ceu_move32_to(b, ceu_reg32(b, 32), 0);

   /* Compute workgroup size */
   uint32_t wg_size[4];
   pan_pack(wg_size, COMPUTE_SIZE_WORKGROUP, cfg) {
      cfg.workgroup_size_x = info->block[0];
      cfg.workgroup_size_y = info->block[1];
      cfg.workgroup_size_z = info->block[2];

      /* Workgroups may be merged if the shader does not use barriers
       * or shared memory. This condition is checked against the
       * static shared_size at compile-time. We need to check the
       * variable shared size at launch_grid time, because the
       * compiler doesn't know about that.
       */
      cfg.allow_merging_workgroups = cs->info.cs.allow_merging_workgroups &&
                                     (info->variable_shared_mem == 0);
   }

   ceu_move32_to(b, ceu_reg32(b, 33), wg_size[0]);

   /* Offset */
   for (unsigned i = 0; i < 3; ++i)
      ceu_move32_to(b, ceu_reg32(b, 34 + i), 0);

   if (info->indirect) {
      /* Load size in workgroups per dimension from memory */
      ceu_index address = ceu_reg64(b, 64);
      ceu_move64_to(b, address,
                    pan_resource(info->indirect)->image.data.bo->ptr.gpu +
                       info->indirect_offset);

      ceu_index grid_xyz = ceu_reg_tuple(b, 37, 3);
      ceu_load_to(b, grid_xyz, address, BITFIELD_MASK(3), 0);

      /* Wait for the load */
      ceu_wait_slot(b, 0);

      /* Copy to FAU */
      for (unsigned i = 0; i < 3; ++i) {
         if (batch->num_wg_sysval[i]) {
            ceu_move64_to(b, address, batch->num_wg_sysval[i]);
            ceu_store(b, ceu_extract32(b, grid_xyz, i), address,
                      BITFIELD_MASK(1), 0);
         }
      }

      /* Wait for the stores */
      ceu_wait_slot(b, 0);
   } else {
      /* Set size in workgroups per dimension immediately */
      for (unsigned i = 0; i < 3; ++i)
         ceu_move32_to(b, ceu_reg32(b, 37 + i), info->grid[i]);
   }

   /* Dispatch. We could be much smarter choosing task size..
    *
    * TODO: How to choose correctly?
    *
    * XXX: Why are compute kernels failing if I make this smaller? Race
    * condition maybe? Cache badnesss?
    */
   ceu_run_compute(b, 10, MALI_TASK_AXIS_Z);
}

void
GENX(csf_launch_xfb)(struct panfrost_batch *batch,
                     const struct pipe_draw_info *info, unsigned count)
{
   ceu_builder *b = batch->csf.cs.builder;

   ceu_move64_to(b, ceu_reg64(b, 24), batch->tls.gpu);

   /* TODO: Indexing. Also, attribute_offset is a legacy feature.. */
   ceu_move32_to(b, ceu_reg32(b, 32), batch->ctx->offset_start);

   /* Compute workgroup size */
   uint32_t wg_size[4];
   pan_pack(wg_size, COMPUTE_SIZE_WORKGROUP, cfg) {
      cfg.workgroup_size_x = 1;
      cfg.workgroup_size_y = 1;
      cfg.workgroup_size_z = 1;

      /* Transform feedback shaders do not use barriers or
       * shared memory, so we may merge workgroups.
       */
      cfg.allow_merging_workgroups = true;
   }
   ceu_move32_to(b, ceu_reg32(b, 33), wg_size[0]);

   /* Offset */
   for (unsigned i = 0; i < 3; ++i)
      ceu_move32_to(b, ceu_reg32(b, 34 + i), 0);

   ceu_move32_to(b, ceu_reg32(b, 37), count);
   ceu_move32_to(b, ceu_reg32(b, 38), info->instance_count);
   ceu_move32_to(b, ceu_reg32(b, 39), 1);

   csf_emit_shader_regs(batch, PIPE_SHADER_VERTEX,
                        batch->rsd[PIPE_SHADER_VERTEX]);
   /* XXX: Choose correctly */
   ceu_run_compute(b, 1, MALI_TASK_AXIS_Z);

   /* Reset registers expected to be 0 for IDVS */
   ceu_move32_to(b, ceu_reg32(b, 31), 0);
   ceu_move32_to(b, ceu_reg32(b, 32), 0);
   ceu_move32_to(b, ceu_reg32(b, 37), 0);
   ceu_move32_to(b, ceu_reg32(b, 38), 0);
}

static mali_ptr
csf_get_tiler_desc(struct panfrost_batch *batch)
{
   struct panfrost_context *ctx = batch->ctx;
   struct panfrost_device *dev = pan_device(ctx->base.screen);

   if (batch->tiler_ctx.bifrost)
      return batch->tiler_ctx.bifrost;

   struct panfrost_ptr t =
      pan_pool_alloc_desc(&batch->pool.base, TILER_CONTEXT);
   pan_pack(t.cpu, TILER_CONTEXT, tiler) {
      unsigned max_levels = dev->tiler_features.max_levels;
      assert(max_levels >= 2);

      /* TODO: Select hierarchy mask more effectively */
      tiler.hierarchy_mask = (max_levels >= 8) ? 0xFF : 0x28;

      /* For large framebuffers, disable the smallest bin size to
       * avoid pathological tiler memory usage. Required to avoid OOM
       * on dEQP-GLES31.functional.fbo.no_attachments.maximums.all on
       * Mali-G57.
       */
      if (MAX2(batch->key.width, batch->key.height) >= 4096)
         tiler.hierarchy_mask &= ~1;

      tiler.fb_width = batch->key.width;
      tiler.fb_height = batch->key.height;
      tiler.heap = batch->ctx->csf.heap.desc_bo->ptr.gpu;
      tiler.sample_pattern =
         pan_sample_pattern(util_framebuffer_get_num_samples(&batch->key));
#if PAN_ARCH >= 9
      tiler.first_provoking_vertex =
         pan_tristate_get(batch->first_provoking_vertex);
#endif

#if PAN_ARCH >= 10
      tiler.geometry_buffer = ctx->csf.tmp_geom_bo->ptr.gpu;
      tiler.geometry_buffer_size = ctx->csf.tmp_geom_bo->kmod_bo->size;
#endif
   }

   batch->tiler_ctx.bifrost = t.gpu;
   return batch->tiler_ctx.bifrost;
}

void
GENX(csf_launch_draw)(struct panfrost_batch *batch,
                      const struct pipe_draw_info *info, unsigned drawid_offset,
                      const struct pipe_draw_start_count_bias *draw,
                      unsigned vertex_count)
{
   struct panfrost_context *ctx = batch->ctx;
   struct panfrost_compiled_shader *vs = ctx->prog[PIPE_SHADER_VERTEX];
   struct panfrost_compiled_shader *fs = ctx->prog[PIPE_SHADER_FRAGMENT];
   bool idvs = vs->info.vs.idvs;
   bool fs_required = panfrost_fs_required(
      fs, ctx->blend, &ctx->pipe_framebuffer, ctx->depth_stencil);
   bool secondary_shader = vs->info.vs.secondary_enable && fs_required;

   assert(idvs && "IDVS required for CSF");

   ceu_builder *b = batch->csf.cs.builder;

   if (batch->draw_count == 0)
      ceu_vt_start(batch->csf.cs.builder);

   csf_emit_shader_regs(batch, PIPE_SHADER_VERTEX,
                        panfrost_get_position_shader(batch, info));

   if (fs_required) {
      csf_emit_shader_regs(batch, PIPE_SHADER_FRAGMENT,
                           batch->rsd[PIPE_SHADER_FRAGMENT]);
   } else {
      ceu_move64_to(b, ceu_reg64(b, 4), 0);
      ceu_move64_to(b, ceu_reg64(b, 12), 0);
      ceu_move64_to(b, ceu_reg64(b, 20), 0);
   }

   if (secondary_shader) {
      ceu_move64_to(b, ceu_reg64(b, 18), panfrost_get_varying_shader(batch));
   }

   ceu_move64_to(b, ceu_reg64(b, 24), batch->tls.gpu);
   ceu_move64_to(b, ceu_reg64(b, 30), batch->tls.gpu);
   ceu_move32_to(b, ceu_reg32(b, 33), draw->count);
   ceu_move32_to(b, ceu_reg32(b, 34), info->instance_count);
   ceu_move32_to(b, ceu_reg32(b, 35), 0);

   /* Base vertex offset on Valhall is used for both indexed and
    * non-indexed draws, in a simple way for either. Handle both cases.
    */
   if (info->index_size) {
      ceu_move32_to(b, ceu_reg32(b, 36), draw->index_bias);
      ceu_move32_to(b, ceu_reg32(b, 39), info->index_size * draw->count);
   } else {
      ceu_move32_to(b, ceu_reg32(b, 36), draw->start);
      ceu_move32_to(b, ceu_reg32(b, 39), 0);
   }

   ceu_move64_to(b, ceu_reg64(b, 40), csf_get_tiler_desc(batch));

   STATIC_ASSERT(sizeof(batch->scissor) == pan_size(SCISSOR));
   STATIC_ASSERT(sizeof(uint64_t) == pan_size(SCISSOR));
   uint64_t *sbd = (uint64_t *)&batch->scissor[0];
   ceu_move64_to(b, ceu_reg64(b, 42), *sbd);

   ceu_move32_to(b, ceu_reg32(b, 44), fui(batch->minimum_z));
   ceu_move32_to(b, ceu_reg32(b, 45), fui(batch->maximum_z));

   if (ctx->occlusion_query && ctx->active_queries) {
      struct panfrost_resource *rsrc = pan_resource(ctx->occlusion_query->rsrc);
      ceu_move64_to(b, ceu_reg64(b, 46), rsrc->image.data.bo->ptr.gpu);
      panfrost_batch_write_rsrc(ctx->batch, rsrc, PIPE_SHADER_FRAGMENT);
   }

   ceu_move32_to(b, ceu_reg32(b, 48), panfrost_vertex_attribute_stride(vs, fs));
   ceu_move64_to(b, ceu_reg64(b, 50),
                 batch->blend | MAX2(batch->key.nr_cbufs, 1));
   ceu_move64_to(b, ceu_reg64(b, 52), batch->depth_stencil);

   if (info->index_size)
      ceu_move64_to(b, ceu_reg64(b, 54), batch->indices);

   uint32_t primitive_flags = 0;
   pan_pack(&primitive_flags, PRIMITIVE_FLAGS, cfg) {
      if (panfrost_writes_point_size(ctx))
         cfg.point_size_array_format = MALI_POINT_SIZE_ARRAY_FORMAT_FP16;

      cfg.allow_rotating_primitives = allow_rotating_primitives(fs, info);

      /* Non-fixed restart indices should have been lowered */
      assert(!cfg.primitive_restart || panfrost_is_implicit_prim_restart(info));
      cfg.primitive_restart = info->primitive_restart;

      cfg.position_fifo_format = panfrost_writes_point_size(ctx)
                                    ? MALI_FIFO_FORMAT_EXTENDED
                                    : MALI_FIFO_FORMAT_BASIC;
   }

   ceu_move32_to(b, ceu_reg32(b, 56), primitive_flags);

   struct pipe_rasterizer_state *rast = &ctx->rasterizer->base;

   uint32_t dcd_flags0 = 0, dcd_flags1 = 0;
   pan_pack(&dcd_flags0, DCD_FLAGS_0, cfg) {
      bool polygon = (u_reduced_prim(info->mode) == MESA_PRIM_TRIANGLES);

      /*
       * From the Gallium documentation,
       * pipe_rasterizer_state::cull_face "indicates which faces of
       * polygons to cull". Points and lines are not considered
       * polygons and should be drawn even if all faces are culled.
       * The hardware does not take primitive type into account when
       * culling, so we need to do that check ourselves.
       */
      cfg.cull_front_face = polygon && (rast->cull_face & PIPE_FACE_FRONT);
      cfg.cull_back_face = polygon && (rast->cull_face & PIPE_FACE_BACK);
      cfg.front_face_ccw = rast->front_ccw;

      cfg.multisample_enable = rast->multisample;

      /* Use per-sample shading if required by API Also use it when a
       * blend shader is used with multisampling, as this is handled
       * by a single ST_TILE in the blend shader with the current
       * sample ID, requiring per-sample shading.
       */
      cfg.evaluate_per_sample =
         (rast->multisample &&
          ((ctx->min_samples > 1) || ctx->valhall_has_blend_shader));

      cfg.single_sampled_lines = !rast->multisample;

      bool has_oq = ctx->occlusion_query && ctx->active_queries;
      if (has_oq) {
         if (ctx->occlusion_query->type == PIPE_QUERY_OCCLUSION_COUNTER)
            cfg.occlusion_query = MALI_OCCLUSION_MODE_COUNTER;
         else
            cfg.occlusion_query = MALI_OCCLUSION_MODE_PREDICATE;
      }

      if (fs_required) {
         struct pan_earlyzs_state earlyzs = pan_earlyzs_get(
            fs->earlyzs, ctx->depth_stencil->writes_zs || has_oq,
            ctx->blend->base.alpha_to_coverage,
            ctx->depth_stencil->zs_always_passes);

         cfg.pixel_kill_operation = earlyzs.kill;
         cfg.zs_update_operation = earlyzs.update;

         cfg.allow_forward_pixel_to_kill =
            pan_allow_forward_pixel_to_kill(ctx, fs);
         cfg.allow_forward_pixel_to_be_killed = !fs->info.writes_global;

         cfg.overdraw_alpha0 = panfrost_overdraw_alpha(ctx, 0);
         cfg.overdraw_alpha1 = panfrost_overdraw_alpha(ctx, 1);

         /* Also use per-sample shading if required by the shader
          */
         cfg.evaluate_per_sample |= fs->info.fs.sample_shading;

         /* Unlike Bifrost, alpha-to-coverage must be included in
          * this identically-named flag. Confusing, isn't it?
          */
         cfg.shader_modifies_coverage = fs->info.fs.writes_coverage ||
                                        fs->info.fs.can_discard ||
                                        ctx->blend->base.alpha_to_coverage;

         cfg.alpha_to_coverage = ctx->blend->base.alpha_to_coverage;
      } else {
         /* These operations need to be FORCE to benefit from the
          * depth-only pass optimizations.
          */
         cfg.pixel_kill_operation = MALI_PIXEL_KILL_FORCE_EARLY;
         cfg.zs_update_operation = MALI_PIXEL_KILL_FORCE_EARLY;

         /* No shader and no blend => no shader or blend
          * reasons to disable FPK. The only FPK-related state
          * not covered is alpha-to-coverage which we don't set
          * without blend.
          */
         cfg.allow_forward_pixel_to_kill = true;

         /* No shader => no shader side effects */
         cfg.allow_forward_pixel_to_be_killed = true;

         /* Alpha isn't written so these are vacuous */
         cfg.overdraw_alpha0 = true;
         cfg.overdraw_alpha1 = true;
      }
   }

   pan_pack(&dcd_flags1, DCD_FLAGS_1, cfg) {
      cfg.sample_mask = rast->multisample ? ctx->sample_mask : 0xFFFF;

      if (fs_required) {
         /* See JM Valhall equivalent code */
         cfg.render_target_mask =
            (fs->info.outputs_written >> FRAG_RESULT_DATA0) & ctx->fb_rt_mask;
      }
   }

   ceu_move32_to(b, ceu_reg32(b, 57), dcd_flags0);
   ceu_move32_to(b, ceu_reg32(b, 58), dcd_flags1);

   uint64_t primsize = 0;
   panfrost_emit_primitive_size(ctx, info->mode == MESA_PRIM_POINTS, 0,
                                &primsize);
   ceu_move64_to(b, ceu_reg64(b, 60), primsize);

   ceu_run_idvs(b, pan_draw_mode(info->mode),
                panfrost_translate_index_size(info->index_size),
                secondary_shader);
}

#define POSITION_FIFO_SIZE (64 * 1024)

void
GENX(csf_init_context)(struct panfrost_context *ctx)
{
   struct panfrost_device *dev = pan_device(ctx->base.screen);
   struct drm_panthor_queue_create qc[] = {{
      .priority = 1,
      .ringbuf_size = 64 * 1024,
   }};

   struct drm_panthor_group_create gc = {
      .compute_core_mask = dev->kmod.props.shader_present,
      .fragment_core_mask = dev->kmod.props.shader_present,
      .tiler_core_mask = 1,
      .max_compute_cores = util_bitcount64(dev->kmod.props.shader_present),
      .max_fragment_cores = util_bitcount64(dev->kmod.props.shader_present),
      .max_tiler_cores = 1,
      .priority = PANTHOR_GROUP_PRIORITY_MEDIUM,
      .queues = DRM_PANTHOR_OBJ_ARRAY(ARRAY_SIZE(qc), qc),
      .vm_id = pan_kmod_vm_handle(dev->kmod.vm),
   };

   int ret =
      drmIoctl(panfrost_device_fd(dev), DRM_IOCTL_PANTHOR_GROUP_CREATE, &gc);

   assert(!ret);

   ctx->csf.group_handle = gc.group_handle;

   /* Get tiler heap */
   struct drm_panthor_tiler_heap_create thc = {
      .vm_id = pan_kmod_vm_handle(dev->kmod.vm),
      .chunk_size = 2 * 1024 * 1024,
      .initial_chunk_count = 5,
      .max_chunks = 64 * 1024,
      .target_in_flight = 65535,
   };
   ret = drmIoctl(panfrost_device_fd(dev), DRM_IOCTL_PANTHOR_TILER_HEAP_CREATE,
                  &thc);

   assert(!ret);

   ctx->csf.heap.handle = thc.handle;

   ctx->csf.heap.desc_bo =
      panfrost_bo_create(dev, pan_size(TILER_HEAP), 0, "Tiler Heap");
   pan_pack(ctx->csf.heap.desc_bo->ptr.cpu, TILER_HEAP, heap) {
      heap.size = 2 * 1024 * 1024;
      heap.base = thc.first_heap_chunk_gpu_va;
      heap.bottom = heap.base + 64;
      heap.top = heap.base + heap.size;
   }

   ctx->csf.tmp_geom_bo = panfrost_bo_create(
      dev, POSITION_FIFO_SIZE, PAN_BO_INVISIBLE, "Temporary Geometry buffer");
   assert(ctx->csf.tmp_geom_bo);

   /* Setup the tiler heap */
   struct panfrost_bo *cs_bo =
      panfrost_bo_create(dev, 4096, 0, "Temporary CS buffer");
   assert(cs_bo);

   struct ceu_queue init_queue = {
      .cpu = cs_bo->ptr.cpu,
      .gpu = cs_bo->ptr.gpu,
      .capacity = panfrost_bo_size(cs_bo) / sizeof(uint64_t),
   };
   const struct ceu_builder_conf bconf = {
      .nr_registers = 96,
      .nr_kernel_registers = 4,
   };
   ceu_builder b;
   ceu_builder_init(&b, &bconf, init_queue);
   ceu_index heap = ceu_reg64(&b, 72);
   ceu_move64_to(&b, heap, thc.tiler_heap_ctx_gpu_va);
   ceu_heap_set(&b, heap);

   struct drm_panthor_queue_submit qsubmit;
   struct drm_panthor_group_submit gsubmit;
   struct drm_panthor_sync_op sync = {
      .flags =
         DRM_PANTHOR_SYNC_OP_SIGNAL | DRM_PANTHOR_SYNC_OP_HANDLE_TYPE_SYNCOBJ,
      .handle = ctx->syncobj,
   };
   uint32_t cs_instr_count = ceu_finish(&b);
   uint64_t cs_start = b.root.gpu;
   uint32_t cs_size = cs_instr_count * 8;

   csf_prepare_qsubmit(ctx, &qsubmit, 0, cs_start, cs_size, &sync, 1);
   csf_prepare_gsubmit(ctx, &gsubmit, &qsubmit, 1);
   ret = csf_submit_gsubmit(ctx, &gsubmit);
   assert(!ret);

   /* Wait before freeing the buffer. */
   drmSyncobjWait(panfrost_device_fd(dev), &ctx->syncobj, 1, INT64_MAX, 0,
                  NULL);
   panfrost_bo_unreference(cs_bo);
}

void
GENX(csf_cleanup_context)(struct panfrost_context *ctx)
{
   struct panfrost_device *dev = pan_device(ctx->base.screen);
   struct drm_panthor_tiler_heap_destroy thd = {
      .handle = ctx->csf.heap.handle,
   };
   int ret;

   /* Make sure all jobs are done before destroying the heap. */
   ret = drmSyncobjWait(panfrost_device_fd(dev), &ctx->syncobj, 1, INT64_MAX, 0,
                        NULL);
   assert(!ret);

   ret = drmIoctl(panfrost_device_fd(dev), DRM_IOCTL_PANTHOR_TILER_HEAP_DESTROY,
                  &thd);
   assert(!ret);

   struct drm_panthor_group_destroy gd = {
      .group_handle = ctx->csf.group_handle,
   };

   ret =
      drmIoctl(panfrost_device_fd(dev), DRM_IOCTL_PANTHOR_GROUP_DESTROY, &gd);
   assert(!ret);

   panfrost_bo_unreference(ctx->csf.heap.desc_bo);
}

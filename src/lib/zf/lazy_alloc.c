/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** "Lazy" allocator implementation. */

#include <limits.h>

#include <zf_internal/utils.h>
#include <zf_internal/lazy_alloc.h>


void
__zf_lazy_alloc_init(struct zf_lazy_alloc_state* state, unsigned max_index,
                     size_t link_offset, size_t link_object_size,
                     void* link_array_base)
{
  /* We need one additional value to indicate that all lazy allocation has been
   * done. */
  zf_assert_lt(max_index, UINT_MAX);

  ci_sllist_init(&state->free_list);
  state->max_index = max_index;
  state->link_offset = link_offset + (intptr_t) link_array_base;
  state->link_object_size = link_object_size;
  state->next_lazy_index = 0;
}


static unsigned zf_lazy_alloc_link_to_index(struct zf_lazy_alloc_state* state,
                                            ci_sllink* free_link)
{
  intptr_t offset = (intptr_t) free_link - state->link_offset;
  zf_assert_equal(offset % state->link_object_size, 0);
  return offset / state->link_object_size;
}


int zf_lazy_alloc(struct zf_lazy_alloc_state* state, unsigned *index_out)
{
  if( state->next_lazy_index <= state->max_index ) {
    *index_out = state->next_lazy_index++;
    return 0;
  }

  if( ci_sllist_is_empty(&state->free_list) )
    return -ENOBUFS;

  *index_out = zf_lazy_alloc_link_to_index(state,
                                           ci_sllist_pop(&state->free_list));
  return 0;
}


void zf_lazy_free(struct zf_lazy_alloc_state* state, ci_sllink* free_link)
{
  ci_sllist_push(&state->free_list, free_link);
}


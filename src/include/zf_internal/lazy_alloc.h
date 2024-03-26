/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INTERNAL_LAZY_ALLOC_H__
#define __ZF_INTERNAL_LAZY_ALLOC_H__


#include <zf_internal/utils.h>


struct zf_lazy_alloc_state {
  ci_sllist free_list;
  unsigned max_index;
  unsigned next_lazy_index;

  /* Offset of first free-link member in array of containers, i.e.
   * &objects[0].free_link */
  intptr_t link_offset;
  /* Length of the object containing the free-link. */
  size_t link_object_size;
};


extern void
__zf_lazy_alloc_init(struct zf_lazy_alloc_state* state, unsigned max_index,
                     size_t link_offset, size_t link_object_size,
                     void* link_array_base);

#define zf_lazy_alloc_init(state, max_index, link_array_base) \
  __zf_lazy_alloc_init(state, max_index,                                      \
                       ZF_MEMBER_OFFSET(typeof(*link_array_base),             \
                                        generic_res.free_link),               \
                       sizeof(*link_array_base), link_array_base)

extern int
zf_lazy_alloc(struct zf_lazy_alloc_state* state, unsigned* index_out);

extern void
zf_lazy_free(struct zf_lazy_alloc_state* state, ci_sllink* free_link);


#endif /* __ZF_INTERNAL_LAZY_ALLOC_H__ */


/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#pragma once

#include <zf_internal/utils.h>

struct zf_allocator {
  char* max_ptr;
  char* cur_ptr;
  char bytes[0] alignas(ZF_CACHE_LINE_SIZE);
};


static inline void zf_allocator_init(zf_allocator* a, size_t size)
{
  a->cur_ptr = a->bytes;
  a->max_ptr = a->bytes + size;
  zf_assert_le(a->cur_ptr, a->max_ptr);
}


static inline void*
zf_allocator_alloc(zf_allocator* a, size_t len)
{
  char* ptr = a->cur_ptr;
  zf_assert_le(a->cur_ptr + len, a->max_ptr);
  if( ! (a->cur_ptr + len <= a->max_ptr) )
    return NULL;

  a->cur_ptr += ROUND_UP(len, ZF_CACHE_LINE_SIZE);
  return ptr;
}


static inline void
zf_allocator_free(zf_allocator* a, void* ptr)
{
  zf_assert_le(ptr, a->max_ptr);
  zf_assert_ge(ptr, a->bytes);
}

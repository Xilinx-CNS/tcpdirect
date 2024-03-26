/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#include <zf_internal/private/zf_hal.h>
#include <zf_internal/attr.h>
#include <zf_internal/utils.h>

int zf_hal_init(struct zf_attr* attr)
{
  if( attr->emu ) {
    zf_log(NULL, "Emulation not supported\n");
    return -ENOTSUP;
  }
  return 0;
}

void* zf_hal_mmap(void* addr, size_t length, int prot,
                  int flags, int fd, off_t offset)
{
  return mmap(addr, length, prot, flags, fd, offset);
}

int zf_hal_munmap(void* addr, size_t length)
{
  return munmap(addr, length);
}

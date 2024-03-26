/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INTERNAL_HUGE_H__
#define __ZF_INTERNAL_HUGE_H__

extern void* __alloc_huge(size_t size);
extern void __free_huge(void* ptr, size_t size);

#endif /* __ZF_INTERNAL_HUGE_H__ */

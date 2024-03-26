/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_STACKDUMP_H__
#define __ZF_STACKDUMP_H__

#include <zf/zf.h>
#include <stddef.h>


ZF_LIBENTRY ZF_COLD int
zf_stack_map(int onload_dh, int stack_shm_id, struct zf_stack** addr_out);

ZF_LIBENTRY ZF_COLD void
zf_stack_dump(struct zf_stack* stack);

ZF_LIBENTRY ZF_COLD void
zf_stack_dump_summary(struct zf_stack* stack);

ZF_LIBENTRY ZF_COLD int
zf_get_all_stack_shm_ids(int onload_dh, int* shm_ids, size_t count);


/* We define a generic class representing structures that may be mapped at the
 * "wrong" location, so that pointers they contain differ from the mapped
 * addresses of the objects to which they refer by some fixed offset. */
template<typename T>
class SkewPointer {
    T* const mapped_addr;
    const ptrdiff_t offset;

    /* Private constructor for recursive case where we already know the
     * offset. */
    SkewPointer(T* mapped_addr, ptrdiff_t offset) :
      mapped_addr(mapped_addr), offset(offset) {}

    /* Allow all instantiations of this template to use others' private
     * constructors. */
    template<typename S> friend class SkewPointer;

  public:
    /* When constructing the object, remember the mapped address of the
     * structure, so that we can access its members, and calculate the offset
     * that we need to apply to pointers contained within. */
    SkewPointer(T* mapped_addr, const T* natural_addr) :
      mapped_addr(mapped_addr),
      offset((char*) mapped_addr - (char*) natural_addr) {}

    /* Convenience constructor for stacks, hiding the details of extracting
     * the natural address from call-sites. */
    SkewPointer(struct zf_stack_impl*);

    /* Apply offsets to pointer members.  These pointers
     * are themselves SkewPointers, so that the offsetting behaviour is
     * recursive. */
    template<typename Member>
    SkewPointer<Member> adjust_pointer(Member* natural_addr) const
    {
      return SkewPointer<Member>((Member*) ((char*) natural_addr + offset),
                                 offset);
    }

    /* Create a SkewPointer from the address of a member in the address space
     * of the current mapping.  Useful when some function wants a pointer to
     * one of our members. */
    template<typename Member>
    SkewPointer<Member> propagate_skew(Member* mapped_addr) const
    {
      return SkewPointer<Member>(mapped_addr, offset);
    }

    /* To allow objects of this class to be used as if they were simple
     * pointers, we supply casts and dereferences. */
    operator T*()   const { return mapped_addr; }
    T* operator->() const { return mapped_addr; }
};

#endif

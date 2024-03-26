/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** Internal TCP zocket functionality
 *
 * This is the internal interface to the TCP zocket.  It contains TCP specific
 * functionality that is related to management of the zocket, rather than the
 * TCP state machine.
 *
 * Functions in this interface are prefixed with zf_tcp_.
 */
#ifndef __ZF_INT_ZF_TCP_H__
#define __ZF_INT_ZF_TCP_H__

#include <zf/zf.h>
#include <zf_internal/zf_stackdump.h>


struct zf_tcp;
struct zf_stack;

/** \brief Take a reference to a zf_tcp
 *
 * \param tcp The TCP to take a reference to
 */
extern ZF_COLD void
zf_tcp_acquire(struct zf_tcp* tcp);


/** \brief Release a reference to a zf_tcp
 *
 * \param tcp The TCP to release a reference to
 *
 * After calling this function the zf_tcp should no longer be accessed as it
 * may have been freed.
 */
extern ZF_COLD void
zf_tcp_release(struct zf_stack* stack, struct zf_tcp* tcp);


/** \brief Allocate and initialise a new zf_tcp
 *
 * \param st      The stack in which to allocate it
 * \param tcp_out On successful return an intialised zf_tcp
 *
 * The lifetime of the zf_tcp is managed by reference count, with it being
 * freed when the reference count drops to zero.  This function initialises
 * the reference count to zero, so the caller must ensure that a reference
 * is acquired appropriately.
 *
 * \see zf_tcp_acquire() zf_tcp_release()
 */
ZF_COLD extern int
zf_tcp_new(struct zf_stack* stack, struct zf_tcp** tcp_out);


/** \brief Release a zf_tcp on stack free
 *
 * On stack shutdown there may remain references from both the TCP state
 * machine and the application.  This function forces release of the zf_tcp
 * whatever state the references are in.
 */
ZF_COLD extern void
zf_tcp_on_stack_free(struct zf_stack* stack, struct zf_tcp* tcp);


/** \brief Dump the stack of a zf_tcp
 */
ZF_COLD extern void
zf_tcp_dump(SkewPointer<zf_stack>, SkewPointer<zf_tcp>);


struct zf_tcp_listen_state;

/** \brief Dump the stack of a zf_tcp
 */
ZF_COLD extern void
zf_tcp_listen_dump(SkewPointer<zf_stack>, SkewPointer<zf_tcp_listen_state>);

#endif /* __ZF_INT_ZF_TCP_H__ */

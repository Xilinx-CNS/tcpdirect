/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  sasha
**  \brief  Standalone waitable for ZF socket shim
**   \date  2015/11/19
**    \cop  (c) Solarflare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ZF_INTERNAL_WAITABLE_EXT_H__
#define __ZF_INTERNAL_WAITABLE_EXT_H__

#include <zf/zf.h>

/** \brief Allocate a user-managed waitable.
 *
 * \return a waitable object to be used with zf_muxer_add() and
 * zf_waitable_event()
 */
ZF_LIBENTRY struct zf_waitable* zf_waitable_alloc(struct zf_stack* st);

/** \brief Free a user-managed waitable
 *
 * This function must be called with a waitable obtained via
 * zf_waitable_alloc() only!
 */
ZF_LIBENTRY void zf_waitable_free(struct zf_waitable* w);

/** \brief Set or unset event on the waitable object
 *
 * It is not recommended to use this function with any waitable except
 * user-managed waitable (i.e. obtained via zf_waitable_alloc()).
 */
ZF_LIBENTRY void
zf_waitable_set(struct zf_waitable* w, uint32_t events, bool set);

/** \brief Add a waitable to a muxer set without checking the stack
 *
 * This is necessary in order to add a waitable allocated with
 * zf_waitable_alloc() to a multiplexer set.
 */
ZF_LIBENTRY int
__zf_muxer_add(struct zf_muxer_set* muxer, struct zf_waitable* w,
               const struct epoll_event* event);

#endif /* __ZF_INTERNAL_WAITABLE_EXT_H__ */

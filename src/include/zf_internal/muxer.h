/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** Multiplexer. */

#ifndef __ZF_INTERNAL_MUXER_H__
#define __ZF_INTERNAL_MUXER_H__

#include <zf/zf.h>
#include <zf_internal/zf_stackdump.h>

#include <ci/tools/sllist.h>

#include <sys/epoll.h>


/* Set of waitables, on which we can wait, and with state indicating readiness.
 */
struct zf_muxer_set {
  struct zf_stack*  stack;

  /* List of waitables that might be ready.  They are added to the list when
   * they are identified as being ready, but are removed only when reported
   * to a caller of zf_muxer_wait(), and so the list might contain items which
   * are no longer ready. */
  ci_sllist         ready_list;

  /* At present we don't maintain a record of all waitables in the set.
   * Instead, the waitables themselves contain a reference to the set.  One
   * side-effect of this is that we need to reference-count the set. */
  uint32_t          refcount;

  /* Have the user called zf_muxer_free()? */
  bool              released;
};


/* Abstract type representing anything that can be multiplexed. */
struct zf_waitable {
  /* Every waitable lives in zero or one muxer sets.  Real epoll sets, in which
   * the relationship between fds and sets is many-to-many, could be
   * implemented in a manner analogous to the handling of non-home-stack
   * members with Onload's epoll3.
   */
  struct zf_muxer_set*   muxer_set;

  /* Link into the muxer's list of (potentially) ready waitables, or NULL if
   * definitely not ready. */
  ci_sllink              ready_link;

  /* Specifies the mask of events in which we are interested, and user data. */
  struct epoll_event     event;

  /* We track the readiness of the waitable in a generic way here, rather than
   * deriving it just-in-time.  This reduces branching inside the muxer-wait
   * loop.  The trade-off is that this mask must always be kept up-to-date. */
  uint32_t               readiness_mask;
};

ZF_HOT static inline void
zf_muxer_mark_waitable_ready(struct zf_waitable* w, uint32_t events)
{
  w->readiness_mask |= events;

   if( (w->event.events & events) && ! ci_sllink_busy(&w->ready_link) )
    ci_sllist_push(&w->muxer_set->ready_list, &w->ready_link);
}


ZF_HOT static inline void
zf_muxer_mark_waitable_not_ready(struct zf_waitable* w, uint32_t events)
{
  w->readiness_mask &= ~events;
}


/* Returns whether the waitable is ready.  The actual return value is the mask
 * of interesting events, but this is an implementation detail and should not
 * be relied on. */
static inline uint32_t
zf_muxer_waitable_is_ready(struct zf_waitable* w)
{
  return w->readiness_mask & w->event.events;
}


extern void zf_waitable_init(struct zf_waitable*);


extern ZF_COLD void zf_waitable_fd_free(struct zf_stack* stack);
extern ZF_COLD void zf_waitable_dump(SkewPointer<zf_waitable> w);

#endif /* __ZF_INTERNAL_MUXER_H__ */

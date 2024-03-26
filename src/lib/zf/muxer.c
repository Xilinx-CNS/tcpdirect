/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** Multiplexer. */

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/muxer.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/zf_stack_impl.h>
#include <zf_internal/zf_stackdump.h>
#include <zf_internal/shim/waitable_ext.h>
#include <zf_internal/private/reactor.h>

#include <stdint.h>
#include <unistd.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <errno.h>

static const zf_logger zf_log_muxer_err(ZF_LC_MUXER, ZF_LL_ERR);


void zf_waitable_init(struct zf_waitable* w)
{
  w->muxer_set = NULL;
  w->ready_link.next = NULL;
  w->event.events = 0;
  w->readiness_mask = 0;
}


static void zf_muxer_assert_valid(struct zf_muxer_set* muxer)
{
  zf_assume(muxer);
  zf_assume(muxer->stack);
  zf_assume_gt(muxer->refcount, 0);

  /* Arbitrary but ample upper bound. */
  const uint32_t max_allowed_refs = 1u << 31;
  zf_assume_le(muxer->refcount, max_allowed_refs);
#ifndef NDEBUG

  /* Assert that we can walk the ready-list in no more steps than there are
   * references to the set. */
  uint32_t steps;
  ci_sllink* link = muxer->ready_list.head;
  for( steps = 0;
       steps <= muxer->refcount && link != CI_SLLIST_TAIL;
       ++steps, link = link->next )
    ;
  /* N.B.: If the set has been released and all waitables are ready, then we
   * will take fully muxer->refcount steps to walk the list. */
  if( steps >= muxer->refcount + 1 ) {
    zf_log_muxer_err(muxer, "Ready-list is corrupt.\n");
    zf_assert(0);
  }
#endif
}


int zf_muxer_alloc(struct zf_stack* stack, struct zf_muxer_set** muxer_out)
{
  struct zf_muxer_set* muxer;
  
  if( zf_stack_alloc_muxer(stack, &muxer) != 0 )
    return -ENOMEM;

  muxer->refcount = 1;
  muxer->stack = stack;
  ci_sllist_init(&muxer->ready_list);

  zf_muxer_assert_valid(muxer);

  *muxer_out = muxer;

  return 0;
}


static void zf_muxer_ref(struct zf_muxer_set* muxer)
{
  zf_muxer_assert_valid(muxer);
  ++muxer->refcount;
}


void zf_muxer_release(struct zf_muxer_set* muxer)
{
  zf_muxer_assert_valid(muxer);

  if( --muxer->refcount == 0 )
    zf_stack_free_muxer(zf_stack_from_zocket(muxer), muxer);
}


/* This implements the API call to free an allocated muxer.  In fact all we
 * need to do is release a reference, but in principle this is a distinct
 * operation.  Internal users of a set should call zf_muxer_release() directly
 * instead of this function. */
void zf_muxer_free(struct zf_muxer_set* muxer)
{
  muxer->released = true;
  zf_muxer_release(muxer);
}


/* This is the common part of zf_muxer_add() and zf_muxer_mod(). */
static void
zf_muxer_set_event(struct zf_waitable* w, const struct epoll_event* event)
{
  w->event = *event;

  /* If the waitable is already ready, add it to the ready-list. */
  if( w->readiness_mask & event->events )
    zf_muxer_mark_waitable_ready(w, w->readiness_mask & event->events);
}


int __zf_muxer_add(struct zf_muxer_set* muxer, struct zf_waitable* w,
                   const struct epoll_event* event)
{
  zf_muxer_assert_valid(muxer);

  if( w->muxer_set != NULL ) {
    if( w->muxer_set->released ) {
      /* If this waitable is a member of already-removed muxer,
       * then we can call zf_muxer_del() freely and re-use this waitable
       * for this new muxer.
       */
      struct zf_muxer_set* old_muxer = w->muxer_set;
      (void) old_muxer;
      zf_assert(old_muxer->refcount > 0);
      zf_muxer_del(w);
    }
    else {
      return w->muxer_set == muxer ? -EALREADY : -EBUSY;
    }
  }
  zf_assert(! ci_sllink_busy(&w->ready_link) );

  zf_muxer_ref(muxer);
  w->muxer_set = muxer;
  zf_muxer_set_event(w, event);

  return 0;
}


int zf_muxer_add(struct zf_muxer_set* muxer, struct zf_waitable* w,
                 const struct epoll_event* event)
{
  zf_muxer_assert_valid(muxer);

  /* Enforce that the waitable belong to the muxer's stack. */
  if( muxer->stack != zf_stack_from_zocket(w) )
    return -EXDEV;

  return __zf_muxer_add(muxer, w, event);
}


int zf_muxer_mod(struct zf_waitable* w, const struct epoll_event* event)
{
  if( w->muxer_set == NULL )
    return -EINVAL;

  zf_muxer_assert_valid(w->muxer_set);

  zf_muxer_set_event(w, event);

  return 0;
}


int zf_muxer_del(struct zf_waitable* w)
{
  if( w->muxer_set == NULL )
    return -EINVAL;

  zf_muxer_assert_valid(w->muxer_set);

  /* Zero out the desired events.  The fast path relies on this for waitables
   * that are not in a set. */
  w->event.events = 0;

  /* Walk the ready-list in search of [w], and remove it if we find it. */
  ci_sllink* link;
  ci_sllink** link_prev = &w->muxer_set->ready_list.head;
  for( link = w->muxer_set->ready_list.head;
       link != CI_SLLIST_TAIL && link != &w->ready_link;
       link_prev = &link->next, link = link->next )
    ;
  if( link == &w->ready_link )
    *link_prev = w->ready_link.next;
  w->ready_link.next = NULL;

  zf_muxer_assert_valid(w->muxer_set);
  zf_muxer_release(w->muxer_set);
  w->muxer_set = NULL;

  return 0;
}


/* Determines whether we have passed a timeout threshold. */
static inline int
zf_muxer_timeout_elapsed(int64_t timeout_ns, uint64_t timeout_threshold)
{
  /* A zero timeout elapses immediately, and a negative timeout never elapses.
   */
  if( timeout_ns <= 0 )
    return timeout_ns == 0;

  /* Check for [frc] having passed [timeout_threshold]. */
  return zf_frc64() - timeout_threshold <= (uint64_t) INT64_MAX;
}


int zf_muxer_wait(struct zf_muxer_set* muxer, struct epoll_event* events,
                  int maxevents, int64_t timeout_ns)
{
  int i = 0, rc;
  uint64_t timeout_threshold = 0;  /* Initialised to placate compiler. */
  bool timeout_initialised = 0;

  zf_muxer_assert_valid(muxer);

  zf_assume_ge(maxevents, 0);

  do {
    rc = zf_reactor_perform(muxer->stack);

    while( ! ci_sllist_is_empty(&muxer->ready_list) && i < maxevents ) {
      struct zf_waitable* w;
      w = ZF_CONTAINER(struct zf_waitable, ready_link,
                       ci_sllist_pop(&muxer->ready_list));
      /* The presence of the waitable on the list does not guarantee its
       * readiness, so we need to check this explicitly. */
      if(ZF_LIKELY( zf_muxer_waitable_is_ready(w) )) {
        events[i] = w->event;
        events[i].events &= w->readiness_mask;
        i++;
      }
    }

    /* Early exit if we found something to report. */
    if(ZF_LIKELY( i != 0 ))
      break;

    if( rc == ZF_REACTOR_PFTF ) {
      struct zf_waitable* w = muxer->stack->pftf.w;
      if( w->muxer_set == muxer ) {
        events[0] = w->event;
        events[0].events = ZF_EPOLLIN_OVERLAPPED;
        zf_log_event_trace(
            muxer->stack, "%s: PFTF data %p len %d\n", __func__,
            muxer->stack->pftf.payload, muxer->stack->pftf.payload_len);
        return 1;
      }
    }

    /* Initialising the timeout state has a non-negligible cost, so we do it
     * only after having polled the stack once without having found any
     * interesting events. */
    if( timeout_ns > 0 && ! timeout_initialised ) {
      struct zf_timekeeping* timekeeping = &muxer->stack->times.time;
      timeout_threshold = zf_frc64() + zf_timekeeping_ns2frc(timekeeping,
                                                             timeout_ns);
      timeout_initialised = 1;
    }

  } while( ! zf_muxer_timeout_elapsed(timeout_ns, timeout_threshold) );

  return i;
}

const struct epoll_event* zf_waitable_event(struct zf_waitable* w)
{
  return &w->event;
}

struct zf_waitable* zf_waitable_alloc(struct zf_stack* st)
{
  struct zf_waitable* w = (struct zf_waitable*)
                          zf_cache_aligned_alloc(sizeof(*w));
  if( w == NULL )
    return NULL;
  zf_waitable_init(w);
  return w;
}

void zf_waitable_free(struct zf_waitable* w)
{
  zf_muxer_del(w);
  free(w);
}

void zf_waitable_set(struct zf_waitable* w, uint32_t events, bool set)
{
  if( set )
    zf_muxer_mark_waitable_ready(w, events);
  else
    zf_muxer_mark_waitable_not_ready(w, events);
}


int zf_waitable_fd_get(struct zf_stack* stack, int* fd)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl,
                                           st, stack);
  int rc, epoll_fd, ef_vi_fd, timer_fd;
  struct epoll_event event;
  
  /* If we've already allocated one, just return that */
  if( sti->waitable_fd.epoll_fd != -1 ) {
    *fd = sti->waitable_fd.epoll_fd;
    return 0;
  }
  
  /* Allocate an epoll set */
  epoll_fd = epoll_create(2);
  if( epoll_fd < 0 )
    goto fail0;
  
  /* Get a timer fd that will trigger frequently enough to serve our
   * TCP timers (iff we have TCP zockets?) 
   */
  timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
  if( timer_fd < 0 )
    goto fail1;
  
  /* Add the ef_vi fd and timer fd to the epoll set */
  event.events = EPOLLIN;
  rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &event);
  if( rc < 0 )
    goto fail2;
  
  /* Get the ef_vi fd for the event queue and add to set */
  for( int nic = 0; nic < stack->nics_n; ++nic ) {
    ef_vi_fd = zf_stack_get_driver_handle(stack, nic);
    rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ef_vi_fd, &event);
    if( rc < 0 ) 
      goto fail2;
  }

  /* Return the epoll_fd and store for future reference */
  *fd = epoll_fd;
  sti->waitable_fd.epoll_fd = epoll_fd;
  sti->waitable_fd.timer_fd = timer_fd;

  return 0;

 fail2:
  close(timer_fd);
 fail1:
  close(epoll_fd);
 fail0:
  return -errno;
}


int zf_waitable_fd_prime(struct zf_stack* stack)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl,
                                           st, stack);
  struct itimerspec timer_value;

  /* TODO make the timeout suitable for the current TCP timer status? 
   * For now just make it expire in 10ms as a suitable interval to
   * poll an idle stack
   */
  timer_value.it_interval.tv_sec = 0;
  timer_value.it_interval.tv_nsec = 0;
  timer_value.it_value.tv_sec = 0;
  timer_value.it_value.tv_nsec = 10000000;
  int rc = timerfd_settime(sti->waitable_fd.timer_fd, 0, &timer_value, NULL);
  if( rc < 0 )
    return -errno;
  
  for( int nic = 0; nic < stack->nics_n; ++nic ) {
    rc = ef_vi_prime(&stack->nic[nic].vi, sti->nic[nic].dh, 
                     ef_eventq_current(&stack->nic[nic].vi));
    if( rc != 0 )
      return rc;
  }

  return 0;
}


void zf_waitable_fd_free(struct zf_stack* stack)
{
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl,
                                           st, stack);

  /* Free the timer fd */
  if( sti->waitable_fd.timer_fd != -1 ) {
    close(sti->waitable_fd.timer_fd);
    sti->waitable_fd.timer_fd = -1;
  }

  /* Free the epoll set */
  if( sti->waitable_fd.epoll_fd != -1 ) {
    close(sti->waitable_fd.epoll_fd);
    sti->waitable_fd.epoll_fd = -1;
  }
}


void zf_waitable_dump(SkewPointer<zf_waitable> w)
{
  if( w->muxer_set ) {
    zf_dump("  mux: set=%p events=%x readiness=%x\n",
            w.adjust_pointer(w->muxer_set), w->event.events, w->readiness_mask);
  }
}


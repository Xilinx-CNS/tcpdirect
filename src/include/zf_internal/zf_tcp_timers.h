/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INT_TCP_TIMERS_H__
#define __ZF_INT_TCP_TIMERS_H__

#include <zf_internal/tcp.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/private/zf_stack_def.h>

#include <zf_internal/utils.h>

#ifndef NDEBUG
static const zf_logger zf_log_timer_trace(ZF_LC_TIMER, ZF_LL_TRACE);
#else
#define zf_log_timer_trace(...) do{}while(0)
#endif

/*  The timer handler does the following:
 *  * only schedule the most immediate timer
 *  * within timer handler decide which timer expired and take proper action
 *  * once timer action has been taken reevaluate which timer is the most
 *    immediate and reschedule
 */

extern int
tcp_tmr(struct zf_tcp* tcp, int timers_expired);


static inline void
zf_tcp_timers_init(struct zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  pcb->timers.token = ZF_WHEEL_EXPIRED_TIMER;
  pcb->timers.running = 0;
}


static inline void
zf_tcp_timers_stop(struct zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  struct zf_stack* stack = zf_stack_from_zocket(tcp);
  zf_timer_del(&stack->times.wheel, tcp - stack->tcp, pcb->timers.token);
  pcb->timers.token = ZF_WHEEL_EXPIRED_TIMER;
}


static inline void
zf_tcp_timers_stop_all(struct zf_tcp* tcp)
{
  zf_tcp_timers_stop(tcp);
  zf_tcp_timers_init(tcp);
}


static inline void
zf_tcp_timers_restart(struct zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  struct zf_stack* stack = zf_stack_from_zocket(tcp);
  /* check any timer is running */
  if( ! pcb->timers.running ) {
    zf_tcp_timers_stop(tcp);
    return;
  }

  zf_tick current_tick = zf_wheel_get_current_tick(&stack->times.wheel);
  zf_tick schedule = 0xFFFFu;

  /* TODO: make sure this loop is unrolled and turned into few cmoves */
  for( int i = 0; i < ZF_TCP_TIMER_COUNT; ++i ) {
    /* TODO ensure cmoves are used */
    zf_tick t = (pcb->timers.running & (1u << i)) ?
      (pcb->timers.expiry[i] - current_tick) :
      0xFFFFu;
    schedule = MIN(schedule, t);
  }
  zf_assert_nequal(schedule, 0xFFFFu);

  zf_log_timer_trace(tcp, "setting timers: zock %d, tok %d, "
                     "sched %d ct %d tr %d\n", (int)(tcp - stack->tcp),
                     pcb->timers.token, schedule, current_tick,
                     pcb->timers.running);
  /* reinstall the timer */
  pcb->timers.token =
    zf_timer_mod(&stack->times.wheel, tcp - stack->tcp, pcb->timers.token,
                 schedule, 1);
}


/* Schedules a postponed work at the end of a tick */
ZF_HOT static inline void
zf_tcp_timers_postpone(struct zf_tcp* tcp)
{
  struct zf_stack* stack = zf_stack_from_zocket(tcp);
  zf_timer_mark_expired(&stack->times.wheel, TCP_ID(stack, tcp));
}


/* Returns non-zero iff a user-visible event occurred.
 * Note this callback handles genuine timers as well as some postponed work.
 *
 * Postponed work is setting/clearing timers.
 * Setting timer is postponed to the end of the tick.
 * Clearing timer: cleared timer might generate this callback at its scheduled time,
 * however, most likely cleared timer will be removed during earlier postponed work.
 */
static inline int
zf_tcp_timers_handle(struct zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;

  if(ZF_LIKELY( pcb->state != CLOSED )) {
    struct zf_stack* stack = zf_stack_from_zocket(tcp);
    zf_tick current_tick = zf_wheel_get_current_tick(&stack->times.wheel);
    int expired = 0;
    for( int i = 0; i < ZF_TCP_TIMER_COUNT; ++i ) {
      int exp = (pcb->timers.running & (1u << i)) &&
                zf_tick_le(pcb->timers.expiry[i], current_tick);
      if( exp ) {
        zf_log_timer_trace(tcp,
                           "expired timer %d: zock %d, tok %d, "
                           "sched %d ct %d tr %d\n", i,
                           (int) TCP_ID(stack, tcp), pcb->timers.token,
                           pcb->timers.expiry[i], current_tick,
                           pcb->timers.running);
      }
      expired |= exp ? (1u << i) : 0;
    }
    pcb->timers.running &= ~ expired;
    int rc = 0;
    if(ZF_UNLIKELY( expired ))
      rc = tcp_tmr(tcp, expired);
    if(ZF_LIKELY( pcb->state != CLOSED )) {
      zf_tcp_timers_restart(tcp);
      return rc;
    }
  }
  /* closed state */
  zf_assert_equal(pcb->timers.running, 0);
  zf_tcp_timers_stop_all(tcp);
  return 0;
}


static inline int
zf_tcp_timers_timer_is_active(struct zf_tcp* tcp, int timer_type)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  return ! ! (pcb->timers.running & 1u << timer_type);
}


static inline void
zf_tcp_timers_timer_start(struct zf_tcp* tcp, int timer_type,
                          zf_tick delay/*, int not_sooner*/)
/* currently all timers will be installed in not_sooner mode */
{
  struct tcp_pcb* pcb = &tcp->pcb;
  struct zf_stack* stack = zf_stack_from_zocket(tcp);

  zf_log_timer_trace(stack, "%s: type %d delay %d\n", __func__,
                     timer_type, delay);

  zf_tick current_tick = zf_wheel_get_current_tick(&stack->times.wheel);
  pcb->timers.running |= 1u << timer_type;
  pcb->timers.expiry[timer_type] = delay + current_tick;
  zf_tcp_timers_postpone(tcp);
}

ZF_HOT static inline void
zf_tcp_timers_timer_stop(struct zf_tcp* tcp, int timer_type)
{
  /* note the event - timer callback - might be still generated at the
   * scheduled time, hence the check of the flag in the callback is essential */
  struct tcp_pcb* pcb = &tcp->pcb;
  pcb->timers.running &= ~(1u << timer_type);
}


static inline zf_tick
zf_tcp_timers_rto_timeout(struct zf_tcp* tcp)
{
  struct tcp_pcb* pcb = &tcp->pcb;
  return ((pcb->sa >> 3) + pcb->sv);
}


static inline zf_tick
zf_tcp_timers_dack_timeout(struct zf_tcp* tcp)
{
  return 2;
}


static inline zf_tick
zf_tcp_timers_timewait_timeout(struct zf_stack* stack)
{
  return stack->config.tcp_timewait_ticks;
}


static inline zf_tick
zf_tcp_timers_finwait_timeout(struct zf_stack* stack)
{
  return stack->config.tcp_finwait_ticks;
}

#endif /* __ZF_INT_TCP_TIMERS_H__ */

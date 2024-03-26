/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** zftimers - fast path code */

#ifndef __ZF_TIMERS_H__
#define __ZF_TIMERS_H__

/* Timer wheel implementation for limited range timeouts,
 * and decreasing precision with timeout duration.
 *
 * This is based to on the discussion in
 * https://lwn.net/Articles/646950/
 * as well as in
 * http://www.cl.cam.ac.uk/research/dtg/lce-pub/public/kjm25/CUED_F-INFENG_TR487.pdf
 *
 * This case is optimized for timeouts that rarely ever expire. That
 * is insertion/modification and cancellation needs to be O(1).
 * The assumptions are that precision is not required
 * especially that precision cannot be achieved without interrupts.
 *
 * There is no guarantee on the order the events are generated.
 *
 * Some care might need to be devised as some timeouts need to happen within
 * specified time (i.e. DACK within 200ms), while others not too soon
 * (e.g. RTO cannot fire too soon as this might be below RTT).
 * This is achieved by rounding up or down the time when timer is added.
 *
 * There is only single timer expiry handler anticipated and it is always passed
 * as a function argument to benefit from optimizations.
 *
 * Timer wheel helds no state per timer and it is assumed that expiry handler
 * can find addressee with timer_id.
 */


#include <zf_internal/utils.h>
#include <zf_internal/bitmap.h>


/* Number of distinct timer ids, e.g. one per a socket */
#define ZF_WHEEL_TIMEOUT_ID_COUNT 128

#define ZF_TIMER_DEBUG(x)

/* Timer implementation consists of set of timer wheels of different precision,
 * ZF_WHEEL_LVL_COUNT indicates the number of these wheels,
 * Number of buckets on each wheel level is determined by
 * ZF_WHEEL_BUCKETS_PER_LEVEL_SHIFT.
 * There is an overlap in precision between wheels,
 * ZF_WHEEL_BUCKETS_PER_LEVEL_PRECISION_SHIFT sets the precision relation
 * between wheel levels, e.g. value of 3 means that a bucket in wheel level 'n + 1'
 * will represent period of time (1u<<3) longer then a bucket in level 'n'.
 */
#define ZF_WHEEL_LVL_COUNT 3
#define ZF_WHEEL_BUCKETS_PER_LEVEL_SHIFT 5
#define ZF_WHEEL_BUCKETS_PER_LEVEL_PRECISION_SHIFT 3
#define ZF_WHEEL_BUCKETS_PER_LEVEL (1u << ZF_WHEEL_BUCKETS_PER_LEVEL_SHIFT)


/* These macros help determine which bits in tick counter could correspond to
 * bucket number in different wheel. */
#define ZF_WHEEL_LVL_BUCKET_LOW_BIT(l) \
                          ((l) * ZF_WHEEL_BUCKETS_PER_LEVEL_PRECISION_SHIFT)
#define ZF_WHEEL_LVL_BUCKET_HIGH_BIT(l) (ZF_WHEEL_LVL_BUCKET_LOW_BIT((l)) + \
                                         ZF_WHEEL_BUCKETS_PER_LEVEL_SHIFT - 1)
#define ZF_WHEEL_LVL_BUCKET_MASK(l) ((2u << ZF_WHEEL_LVL_BUCKET_HIGH_BIT(l)) - \
                                     (1u << ZF_WHEEL_LVL_BUCKET_LOW_BIT(l)))
/* precision of bucket at level l in ticks */
#define ZF_WHEEL_LVL_PRECISION(l) (ZF_WHEEL_LOWEST_PRECISION << \
                                   ZF_WHEEL_LVL_BUCKET_LOW_BIT(l))

/* Max number of ticks entire timer wheel on all levels can represent */
#define ZF_WHEEL_MAX_TICKS \
            ((2u << ZF_WHEEL_LVL_BUCKET_HIGH_BIT(ZF_WHEEL_LVL_COUNT - 1)) - 1)

/* Value of token indicating the timer has expired */
#define ZF_WHEEL_EXPIRED_TIMER 0

/* helper macros allowing forwarding timer args through function stack levels */
#define ZF_WHEEL_EXPIRE_ARG_DECL \
                            int (*expire)(void*, zf_timer_id), void* opaque
#define ZF_WHEEL_EXPIRE_ARG_FWD expire, opaque
#define ZF_WHEEL_EXPIRE_CALL(id) expire(opaque,(id))



typedef uint64_t zf_timeout_unit;
/* tick unit, this needs to be able to fit at least MAX_TICK_COUNT * 2 */
typedef uint16_t zf_tick;
typedef uint8_t zf_timer_id;
/* a single number determining position of timer in the wheel */
typedef uint8_t zf_lvl_bucket;

typedef struct zf_bitmap<ZF_WHEEL_TIMEOUT_ID_COUNT> zf_bucket;

/* token is what is passed to app but internally it is lvl_bucket */
typedef zf_lvl_bucket zf_timer_token;

/* some assumption on bitmap */
_Static_assert(ZF_WHEEL_TIMEOUT_ID_COUNT <= 256, "Invalid constant");
_Static_assert(zf_bucket::WORD_BIT_COUNT == 64, "Invalid constant");


struct zf_wheel {
  zf_tick current_tick;
  /* This is expired bucket (index 0) and 3 wheels */
  zf_bucket bucket[ZF_WHEEL_LVL_COUNT * ZF_WHEEL_BUCKETS_PER_LEVEL + 1];
};
typedef struct zf_wheel zf_wheel;


static inline zf_tick
zf_wheel_get_current_tick(zf_wheel* wheel)
{
  return wheel->current_tick;
}

static inline bool zf_tick_le(zf_tick a, zf_tick b)
{
  return ((int16_t)(a - b)) <= 0;
}

#define topsetbit(x,width) (__builtin_clzl((x)) ^ \
                            (sizeof(unsigned long) * 8 - 1))

static inline int
zf_timer_tick2level_bucket(zf_wheel* w, zf_tick t, int not_sooner)
{
  /* we allow big timers, but they are trimmed to max anyway */
  t = MIN(t, ZF_WHEEL_MAX_TICKS);
  if( t == 0)
    return 0; /* TODO optimize branch */
  unsigned s = ZF_WHEEL_BUCKETS_PER_LEVEL_SHIFT -
               ZF_WHEEL_BUCKETS_PER_LEVEL_PRECISION_SHIFT;
  unsigned t2 = (t + 1) >> s;
  /* Value passed to topsetbit cannot be 0 and we do not want to use
   * last bucket on a level as after rounding up wrap around could be faced,
   * making hard to discriminate expired and far in the distance timers */
  unsigned lvl = topsetbit( t2 | 1, ZF_WHEEL_BUCKETS_PER_LEVEL) /
                 ZF_WHEEL_BUCKETS_PER_LEVEL_PRECISION_SHIFT;

  /* word on rounding up:
   * It might cause a timer to fall into the next bucket,
   * and this might but this will not be the bucket under cursor as it has been
   * provisioned to have lvl increased above. */
  unsigned bucket = ((w->current_tick + t +
               ((!! not_sooner) << (ZF_WHEEL_LVL_BUCKET_LOW_BIT(lvl) - 1))) >>
                ZF_WHEEL_LVL_BUCKET_LOW_BIT(lvl)) &
               (ZF_WHEEL_BUCKETS_PER_LEVEL - 1);
  unsigned lvl_bucket = (lvl << ZF_WHEEL_BUCKETS_PER_LEVEL_SHIFT) + bucket + 1;
  zf_assert_lt(bucket, ZF_WHEEL_BUCKETS_PER_LEVEL);
  zf_assert_lt(lvl, ZF_WHEEL_LVL_COUNT);
  zf_assert_lt(lvl_bucket,
               sizeof(((zf_wheel*)NULL)->bucket) / sizeof(zf_bucket));
  return lvl_bucket;
}


static inline int
zf_timer_is_armed(zf_wheel* w, zf_timer_id timer_id, zf_timer_token token)
{
  return zf_bitmap_test_bit(&w->bucket[token], timer_id);
}


static inline void
__zf_timer_add(zf_wheel* w, zf_timer_id timer_id, zf_lvl_bucket lvl_bucket)
{
  zf_bitmap_set_bit(&w->bucket[lvl_bucket], timer_id);
}


static inline void
zf_timer_mark_expired(zf_wheel* w, zf_timer_id timer_id)
{
  __zf_timer_add(w, timer_id, 0);
}


static inline zf_timer_token
zf_timer_add(zf_wheel* w, zf_timer_id timer_id, zf_tick t, int not_sooner)
{
  zf_assert_le(t, ZF_WHEEL_MAX_TICKS);
  zf_lvl_bucket lvl_bucket = zf_timer_tick2level_bucket(w, t, not_sooner);
  __zf_timer_add(w, timer_id, lvl_bucket);
  return lvl_bucket;
}


static inline void
zf_timer_del(zf_wheel* w, zf_timer_id timer_id, zf_timer_token token)
{
  zf_bitmap_clear_bit(&w->bucket[token], timer_id);
}


static inline zf_timer_token
zf_timer_mod(zf_wheel* w, zf_timer_token timer_id, zf_timer_token token,
             zf_tick t, int not_sooner)
{
  t = MIN(t, ZF_WHEEL_MAX_TICKS - 64);
  int lvl_bucket = zf_timer_tick2level_bucket(w, t, not_sooner);
  zf_timer_del(w, timer_id, token);
  __zf_timer_add(w, timer_id, lvl_bucket);
  return lvl_bucket;
}


static inline zf_timer_token
zf_timer_add_abs(zf_wheel* w, zf_timer_token timer_id, zf_tick t,
                 int not_sooner)
{
  return zf_timer_add(w, timer_id, t - w->current_tick, not_sooner);
}


static inline zf_timer_token
zf_timer_mod_abs(zf_wheel* w, zf_timer_token timer_id, zf_timer_token token,
                 zf_tick t, int not_sooner)
{
  return zf_timer_mod(w, timer_id, token, t - w->current_tick, not_sooner);
}


/* Returns non-zero iff a user-visible event occurred */
static inline int
__zf_wheel_flush_one_expired(zf_bucket* bucket, ZF_WHEEL_EXPIRE_ARG_DECL)
{
  zf_bucket::word* bw = bucket->b;
  int base = 0;
  for( ; bw < bucket->b + zf_bucket::WORD_COUNT;
       ++bw, base += zf_bucket::WORD_BIT_COUNT ) {
    if( *bw ) {
      int bit = zf_bitmap_word_pop_bit(bw);
      return ZF_WHEEL_EXPIRE_CALL(base + bit);
    }
  }
  return 0;
}


/* Returns non-zero iff a user-visible event occurred. */
static inline int
__zf_wheel_flush_expired(zf_bucket* bucket, ZF_WHEEL_EXPIRE_ARG_DECL)
{
  zf_bucket::word* bw = bucket->b;
  int base = 0;
  int event_occurred = 0;
  for( ; bw < bucket->b + zf_bucket::WORD_COUNT;
      ++bw, base += zf_bucket::WORD_BIT_COUNT ) {
    while( *bw ) {
      int bit = zf_bitmap_word_pop_bit(bw);
      event_occurred |= ZF_WHEEL_EXPIRE_CALL(base + bit);
    }
  }
  return event_occurred;
}


static inline int
zf_wheel_flush_expired(zf_wheel* w, ZF_WHEEL_EXPIRE_ARG_DECL)
{
  return
    __zf_wheel_flush_expired(&w->bucket[0], ZF_WHEEL_EXPIRE_ARG_FWD);
}


/* we do a tick, however we might need to catch up first.  Returns non-zero iff
 * a user-visible event occurred. */
static inline int
zf_wheel_tick(zf_wheel* w, zf_tick new_current_tick, ZF_WHEEL_EXPIRE_ARG_DECL)
{
  /* note we coalesce outstanding timers so that the value of current_tick
   * can catch up before expiring outstanding timers,
   * This way in cases when timout handler rearms timers, it will use
   * up to date value of current_tick */

  if( w->current_tick == new_current_tick )
    return __zf_wheel_flush_one_expired(&w->bucket[0], ZF_WHEEL_EXPIRE_ARG_FWD);

  int event_occurred = 0;

  while( w->current_tick != new_current_tick ) {
    ++w->current_tick;
    if( w->current_tick == new_current_tick ) {
      /* these timeouts must have expired at least a tick ago and are
       * still here, we flush them at once */
      event_occurred |= __zf_wheel_flush_expired(&w->bucket[0],
                                                 ZF_WHEEL_EXPIRE_ARG_FWD);
    }
    for( int lvl = 0; lvl < ZF_WHEEL_LVL_COUNT; ++lvl )
    {
      int bucket = (w->current_tick >> ZF_WHEEL_LVL_BUCKET_LOW_BIT(lvl)) &
                   (ZF_WHEEL_BUCKETS_PER_LEVEL - 1);
      int ptr = bucket + 1 + lvl * ZF_WHEEL_BUCKETS_PER_LEVEL;
      ZF_TIMER_DEBUG(printf("wheel lvl %d bucket %d expired ptr %d\n",
                            lvl, bucket, ptr));
      zf_bitmap_join_and_reset(&w->bucket[0], &w->bucket[ptr]);
      /* Only pop higher order wheel timers in single bucket once...
       * Though we could do every time if this is more optimal (branching). */
      if( ((1u << ZF_WHEEL_BUCKETS_PER_LEVEL_PRECISION_SHIFT) - 1) !=
          (bucket & ((1u << ZF_WHEEL_BUCKETS_PER_LEVEL_PRECISION_SHIFT) - 1)) )
        break;
    }
  }
  /* w->bucket[0] contains entries that should expire by the end of this tick */
  return event_occurred;
}


static inline int
zf_wheel_tick_advance(zf_wheel* w, zf_tick tick_delta, ZF_WHEEL_EXPIRE_ARG_DECL)
{
  ZF_TIMER_DEBUG({
    if( tick_delta )
      printf("tick: %d -> %d\n", w->current_tick, (zf_tick)(w->current_tick + tick_delta));
  });
  return zf_wheel_tick(w, w->current_tick + tick_delta, ZF_WHEEL_EXPIRE_ARG_FWD);
}


extern void
zf_timer_wheel_init(zf_wheel* w, zf_tick start_tick);

extern void
zf_timer_wheel_fini(zf_wheel* w);


#endif

/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INT_TCP_OPT_H__
#define __ZF_INT_TCP_OPT_H__

#include <zf/zf.h>


#ifndef TCP_TMR_INTERVAL
#define TCP_TMR_INTERVAL       90  /* The TCP timer interval in milliseconds. */
#endif /* TCP_TMR_INTERVAL */


/**
 * TCP_INITIAL_RTO: The initial TCP retransmission timeout, in ms
 * RFC6298 2.1 requires it to be 1sec
 */
#define TCP_INITIAL_RTO                1000

/**
 * TCP_WND: The size of a TCP window. 
 */
#ifndef TCP_WND
#define TCP_WND                         65535
#endif


/**
 * TCP_TTL: Default Time-To-Live value.
 */
#ifndef TCP_TTL
#define TCP_TTL                         255
#endif


/**
 * TCP_SND_QUEUELEN: TCP sender buffer space
 */
#ifndef TCP_SND_QUEUELEN
#define TCP_SND_QUEUELEN                64
#endif


/**
 * TCP_SND_BUF_ADVERTISEMENT_THRESHOLD: How much send-buffer space must be
 * available for a zocket to be advertised as writable?
 *
 * We advertise writability only when the sendq has space above a certain
 * threshold.  We measure this threshold in bytes, which is safe despite
 * the sendq size being measured in packets as snd_buf is reduced by the
 * MSS for each packet in the queue.
 */
#ifndef TCP_SND_BUF_ADVERTISEMENT_THRESHOLD
#define TCP_SND_BUF_ADVERTISEMENT_THRESHOLD(max_snd_buf) ((max_snd_buf) / 4)
#endif


/**
 * TCP_WND_UPDATE_THRESHOLD: difference in window to trigger an
 * explicit window update
 */
#ifndef TCP_WND_UPDATE_THRESHOLD
#define TCP_WND_UPDATE_THRESHOLD   (TCP_WND / 8)
#endif


/**
 * The time to spend in TIME-WAIT in ms
 */
#define ZF_TCP_TIMEWAIT_TIME_MS 120000


#endif /* __ZF_INT_TCP_OPT_H__ */


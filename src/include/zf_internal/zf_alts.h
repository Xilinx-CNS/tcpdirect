/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INT_ZF_ALTS_H__
#define __ZF_INT_ZF_ALTS_H__

#include <zf/zf.h>
#include <zf_internal/zf_stackdump.h>
#include <zf_internal/tcp_types.h>
#include <zf_internal/zf_pool.h>

#include <etherfabric/ef_vi.h>


struct zf_tcp;
struct zf_alt {
  int handle; /* Kernel-level handle for this alternative */

  static constexpr int MAX_ALTERNATIVES = 17; /* Maximum alts a VI can have */

  uint16_t n_queued_packets; /* Number of packets queued in this alt */
  uint8_t is_draining; /* Set while packets are draining to the output */
  uint8_t is_allocated; /* Set while allocated to a zocket */

  /* The following is all conceptually in the wrong place.  We would
   * ultimately like to support a set of messages from different
   * zockets (TCP or UDP) queued on a single alternative.  This state
   * all relates to the single zocket that we currently allow.
   */
  union {
    struct {
      uint32_t alt_snd_nxt; /* Sequence number of next byte sent into this alt */
      uint32_t first_byte; /* Sequence number of first byte of queued data */
      /* Queued data on this alternative
       * - begin: the first queued segment
       * - middle: the last sent segment, or the last rebuilt segment during
       *           rebuild
       * - end: the last queued segment
       * The queue should be in one of the following states
       * - data queued: begin == middle < end
       * - rebuilding: begin < middle < end
       * - completing: begin < middle == end
       * Packets used on the altq are freed on completion, ie when the queue
       * is drained and we have either cancelled or sent the contents.  We
       * do not free the packets when the queue is drained for a rebuild.
       */
      tcp_send_queue altq;
    } tcp;
  };

  /* We are currently tying each alternative to a single zocket */
  struct zf_tcp* alt_zocket;

 /* When we transfer the altq to the sendq we want to coalesce, which
  * implies we need to copy the data to new pkts, as the altq pkts are still
  * in use until the alt send completes.  Note that although the pkts may
  * already be completed by the hw by the time we copy to the sendq we will
  * not have picked up those events and freed the pkts.
  *
  * This means that we must not poll between performing the send and copying
  * the data to the sendq.
  */
  pkt_id prealloc[TCP_SND_QUEUE_SEG_COUNT];
  int n_prealloc;
};


/* We can fill the altq, plus we can mirror that in our pre-allocated pkts
 * for copying to the sendq.
 */
static const inline unsigned zf_alternatives_max_pkt_bufs_usage(zf_stack* st)
  { return TCP_SND_QUEUE_SEG_COUNT * 2; }


struct zf_stack;
struct tcp_pcb;
/* Handle a TX_ALT event received from the NIC. */
int zf_alternatives_handle_event(struct zf_stack* st, int nic,
                                 ef_event* ev);


/* Make progress on rebuilding alts by pushing as much data as
 * possible to the TX ring and marking alts as complete once all data
 * is pushed. */
void zf_alternatives_resend(struct zf_stack*);


/* Reinitialise an alt's TCP sequence number from the given zocket. */
void zft_alt_reset(struct zf_stack* stack,
                   struct zf_alt* alt,
                   struct tcp_pcb* pcb);


extern void
zf_alt_dump(SkewPointer<zf_stack_impl> stimpl, zf_althandle alt_id);


/* Buffering model for alternatives. */

struct zf_alt_buffer_model {
  struct ef_vi_nic_type* nic_type;
  union {
    struct {
      uint32_t total_buffers;
      uint32_t buffer_size;
      uint32_t words_per_buffer;
      uint32_t n_alts;
      struct {
        uint32_t head_ptr;
        uint32_t tail_ptr;
      } alt[zf_alt::MAX_ALTERNATIVES];
    } medford;
  };
};


struct zf_alt_buffer_model;
struct zf_attr;
/* Initialise the buffer model at start-of-day. */
int zf_altbm_init(struct zf_alt_buffer_model* bm,
                  struct zf_stack_impl*, int nic_no,
                  struct zf_attr* attr);


/* Return the number of bytes of user payload data that can be sent
 * into this alt (assuming they're all in one packet). */
unsigned zf_altbm_bytes_free(struct zf_alt_buffer_model* bm,
                             int althandle);


/* Simulate sending a packet into this alt. Return false if it cannot
 * be sent correctly; otherwise update the state to indicate its
 * presence and return true. */
int zf_altbm_send_packet(struct zf_alt_buffer_model* bm,
                         int althandle,
                         unsigned size_bytes);


/* Undo the effects of zf_altbm_send_packet(), to account for errors
 * which happen after it has returned true. This function MUST be
 * called only after zf_altbm_send_packet() has returned true, and the
 * size_bytes parameter MUST be the same. */
void zf_altbm_unsend_packet(struct zf_alt_buffer_model* bm,
                            int althandle,
                            unsigned size_bytes);


/* Simulate draining all packets from an alt. */
void zf_altbm_alt_reset(struct zf_alt_buffer_model* bm,
                        int althandle);


#endif /* __ZF_INT_ZF_ALTS_H__ */

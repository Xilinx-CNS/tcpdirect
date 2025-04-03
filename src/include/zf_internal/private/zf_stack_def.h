/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#ifndef __ZF_INTERNAL_STACK_DEF_H__
#define __ZF_INTERNAL_STACK_DEF_H__

#include <zf/zf.h>
#include <zf_internal/utils.h>
#include <zf_internal/zf_pool.h>
#include <zf_internal/rx_types.h>
#include <zf_internal/tx_types.h>
#include <zf_internal/zf_tcp_impl_types.h>
#include <zf_internal/tcp_types.h>
#include <zf_internal/udp_rx_types.h>
#include <zf_internal/udp_tx.h>
#include <zf_internal/rx_table_types.h>
#include <zf_internal/timekeeping_types.h>
#include <zf_internal/timers.h>
#include <zf_internal/zf_alts.h>
#include <zf_internal/allocator.h>
#include <zf_internal/zf_stack_common.h>
#include <zf_internal/rx_res.h>
#include <zf_internal/tx_res.h>
#include <zf_internal/tx_req.h>
#include <zf_internal/tx_reports.h>
#include <zf_internal/zf_pool_res.h>
#include <zf_internal/lazy_alloc.h>
#include <zf_internal/bond_types.h>

#include <etherfabric/ef_vi.h>

#include <net/if.h>

enum {
  ZF_STACK_RX_TABLE_TCP,
  ZF_STACK_RX_TABLE_TCP_LISTEN,
  ZF_STACK_RX_TABLE_UDP,
  ZF_STACK_RX_TABLE_COUNT
};

struct zf_stack_nic {
  ef_vi vi;
  ef_vi tx_vi;
  zf_tx_req_id* tx_reqs;
  unsigned tx_reqs_added;
  unsigned tx_reqs_removed;
  unsigned tx_reqs_mask;
  uint8_t mac_addr[ETH_ALEN];
  uint16_t rx_prefix_len;
  uint16_t rx_ring_refill_batch_size;
  /* PIO */
  struct {
    uint16_t len;
    int busy;
  } pio;
  ci_sllist pollout_req_list;
  uint32_t ctpio_allowed; /* CTPIO is allowed for packets of at most
                             this many bytes */
};

struct zf_stack {
  static constexpr unsigned MAGIC_VALUE = 0x70805040;
  static constexpr unsigned MAGIC_DESTROYED_VALUE = 0x7F8F5F4F;
  unsigned magic;
  char st_name[ZF_STACK_NAME_SIZE]; /* Not necessarily null-terminated */

  struct {
    zf_timekeeping time;
    zf_wheel wheel;
  } times;

  uint16_t reactor_spin_count; /*< maximum reactor spin count */
  /* how often to attempt to refill ring in the inner reactor loop */
  uint16_t rx_ring_refill_interval;

  /* Per-NIC state */
  struct zf_stack_nic nic[ZF_MAX_NICS];
  uint8_t nics_n;
  uint8_t next_poll_nic;

  /* Needed to determine whether we are running on a bonded interface */
  uint32_t encap_type;

  /* LLAP version and hwports */
  struct zf_bond_state bond_state;

  /* RX-lookup tables. */
  struct zf_rx_table* rx_table[ZF_STACK_RX_TABLE_COUNT];

  /* Bitmap indicating which TCP zockets have deferred RX processing pending.
   * We can't use zf_bitmap as that's already been defined to be 128-bit by
   * the timers implementation. */
  uint64_t tcp_deferred_rx_bitmap;
  uint64_t udp_deferred_rx_bitmap;

  /* Bitmap indicating which alternative queues need rebuilding in the
   * background. */
  uint32_t alts_need_rebuild;

  /* Bitmap indicating which alternative queues are currently being
   * rebuilt in the background. */
  uint32_t alts_rebuilding;

  /* Global listen "queue".  See the definition of the type for a discussion of
   * the way this works. */
  struct zf_tcp_listenq listenq;

  /* For now, we can process at most one packet from the future at a time. */
  static constexpr int FUTURE_NIC_INVALID = -1;
  int future_nic_id;
  pkt_id future_packet_id;
  const char* efct_current_rx;
  struct {
    zf_waitable* w;
    unsigned frame_len;
    char* payload;
    char* copied_payload;
    unsigned payload_len;
    /* Indicates that after overlapped pftf processing there is an outstanding
     * user visible event to be reported by reactor/muxer without delay.
     * Typically set when unrelated user visible event interrupted pftf.
     */
    unsigned event_occurred_carry;
  } pftf;


  zf_stack_flag flags;

  uint32_t ctpio_max_frame_len;

  /* bulky items at the end */
  struct zf_pool pool;

  static constexpr unsigned MAX_ZOCKET_COUNT = ZF_ZOCKET_ID_MAX + 1;
  /* Arrays of fast-path zocket state. */
  struct zf_udp_rx udp_rx[MAX_ZOCKET_COUNT];
  struct zf_udp_tx udp_tx[MAX_ZOCKET_COUNT];
  struct zf_tcp tcp[MAX_ZOCKET_COUNT];
  struct zf_tcp_listen_state tcp_listen[MAX_ZOCKET_COUNT];

  static constexpr unsigned MAX_MUXER_COUNT = MAX_ZOCKET_COUNT;
  zf_muxer_set muxer[MAX_MUXER_COUNT];

  /* Fast-path state for TCP alternatives */
  int tcp_alt_ack_rewind;

  static constexpr int MAX_ALTERNATIVES = 17; /* Maximum alts a VI can have */
  int tcp_alt_first_ack[MAX_ALTERNATIVES]; /* ACK field from first packet
                                              in the queue */

  /* Non fast path items that need to be accessible as part of
   * protocol processing */

  /* A stack is waitable, and is ready for EPOLLSTACKHUP if and only if it is
   * quiescent. */
  struct zf_waitable w;
  /* Keep track of how far we are from quiescence. */
  int busy_refcount;

  struct zf_stack_config config;
  struct zf_tx_reports::queue tx_reports;

  uint16_t tcp_initial_cwnd;

  struct {
    int ring_refill_nomem;
    /* rx discards of each type */
    ci_uint32 discards[EF_EVENT_RX_DISCARD_MAX];
    uint32_t non_tcpudp;
    unsigned cplane_alien_ifindex;
    uint32_t tcp_retransmits;
  } stats;
};


/* This count is empirical.  Ideally we would calculate the allocation size,
 * but this would need to be reworked if and when we change RX tables to be
 * sparse, so we settle with this for now. */
#define ZF_STACK_HUGE_PAGE_COUNT 10
#define ZF_STACK_ALLOC_SIZE      (ZF_STACK_HUGE_PAGE_COUNT * HUGE_PAGE_SIZE)

#define ZF_RES_NIC_FLAG_VLAN_FILTERS 0x1
#define ZF_RES_NIC_FLAG_RX_LL        0x2
#define ZF_RES_NIC_FLAG_TX_LL        0x4
#define ZF_RES_NIC_FLAG_RX_REF       0x8
#define ZF_RES_NIC_FLAG_CTPIO_ONLY   0x10
#define ZF_RES_NIC_FLAG_PIO          0x20

#include <onload/version.h>
#define ZF_VERSION_LENGTH_MAX OO_VER_STR_LEN

struct zf_stack_res_nic {
  /* handle for accessing the driver */
  ef_driver_handle dh;
  /* protection domain */
  struct ef_pd pd;
  struct ef_pio pio;
  char if_name[IF_NAMESIZE]; /*< NIC's interface.  Slave-name when bonded. */
  int ifindex; /*< ifindex for routing multicast - could be vlan */
  int ifindex_sfc; /*< ifindex of underlaying sfc nic non-vlan tagged */
  int hwport;
  unsigned flags; /*< flags indicating supported features for this nic */
};

/* here we hide away all stuff that is not needed on critical path */
struct zf_stack_impl {
  struct zf_stack st;

  /* Shared-memory ID for stack. */
  int shm_id;

  pid_t pid;

  /* Per-NIC state */
  struct zf_stack_res_nic nic[ZF_MAX_NICS];

  /* Details of stack interface, as specified in the "interface" attribute. */
  char sti_if_name[IF_NAMESIZE];
  int sti_ifindex;
  uint16_t sti_vlan_id;
  uint8_t sti_src_mac[ETH_ALEN];

  struct zf_pool_res pool_res;

  /* RX-lookup tables. */
  struct zf_rx_table_res* rx_table_res[ZF_STACK_RX_TABLE_COUNT];

  /* Non-datapath zocket state.  These are processed by macros, so the
   * corresponding fields must all have the same name, but the types may differ
   * as necessary. */

  struct {
    struct zf_rx_res resources[zf_stack::MAX_ZOCKET_COUNT];
    struct zf_lazy_alloc_state alloc_state;
  } udp_rx;

  struct {
    struct zf_tx_res resources[zf_stack::MAX_ZOCKET_COUNT];
    struct zf_lazy_alloc_state alloc_state;
  } udp_tx;

  struct {
    struct zf_rx_res resources[zf_stack::MAX_ZOCKET_COUNT];
    struct zf_lazy_alloc_state alloc_state;
  } tcp;

  struct {
    struct zf_rx_res resources[zf_stack::MAX_ZOCKET_COUNT];
    struct zf_lazy_alloc_state alloc_state;
  } tcp_listen;

  struct {
    struct { zf_generic_res generic_res; } resources[zf_stack::MAX_MUXER_COUNT];
    struct zf_lazy_alloc_state alloc_state;
  } muxer;

  int max_udp_rx_endpoints;
  int max_udp_tx_endpoints;
  int max_tcp_endpoints;
  int max_tcp_listen_endpoints;

  int tcp_syn_retries;
  int tcp_synack_retries;
  int tcp_retries;
  int arp_reply_timeout;

  /*adding all the zf attributes*/
  int sti_ctpio;
  char sti_ctpio_mode[8];  
  int sti_alt_buf_size;
  int sti_alt_count;
  int sti_rx_ring_max;
  int sti_rx_ring_refill_batch_size;
  int sti_rx_timestamping;
  int sti_tcp_alt_ack_rewind;
  int sti_tcp_delayed_ack;
  int sti_tcp_finwait_ms;
  int sti_tcp_timewait_ms;
  int sti_tcp_wait_for_time_wait; 
  int sti_tx_ring_max;
  int sti_tx_timestamping;
  int sti_ctpio_max_frame_len;
  int sti_force_separate_tx_vi;
  int sti_pio;
  int sti_reactor_spin_count;
  int sti_rx_ring_refill_interval;
  int sti_udp_ttl;
  uint64_t sti_log_level;
  
  int n_alts; /* Number of alternatives actually allocated to this VI */
  struct zf_alt alt[zf_stack::MAX_ALTERNATIVES]; /* indexed by ef_vi ID */
  struct zf_alt_buffer_model alt_buf_model;

  struct {
    int epoll_fd;
    int timer_fd;
  } waitable_fd;

  /* Size of stack and all trailing data. */
  size_t alloc_len;

  /* Natural mapping address for the stack. */
  const struct zf_stack_impl* natural_sti_addr;

  /* Current version of the stack. */
  char sti_on_version[ZF_VERSION_LENGTH_MAX + 1];
  char sti_zf_version[ZF_VERSION_LENGTH_MAX + 1];

  /* Onload driver handle for shared-memory purposes. */
  int onload_dh;

  /* Must be last field */
  zf_allocator alloc;
};


static_assert(sizeof(zf_stack_impl) < HUGE_PAGE_SIZE,
              "zf_stack_impl struct need to fit into single huge page");


/* Infers address of zf_stack from a zocket (or any member of ztack),
 * based on assumption that zf_stack starts at beginning of huge page, and
 * zocket address is within the same huge page */
template <typename Zocket>
static inline zf_stack* zf_stack_from_zocket(Zocket* zock)
{
  auto p = reinterpret_cast<char*>(zock);
  auto i = p - reinterpret_cast<char*>(0);
  zf_stack* z = reinterpret_cast<zf_stack*>(p - (i & (HUGE_PAGE_SIZE - 1)));
  zf_assert_equal(z->magic, zf_stack::MAGIC_VALUE);
  return z;
}


static inline ef_vi* zf_stack_nic_tx_vi(zf_stack_nic* nic) {
  return nic->tx_vi.inited ? &nic->tx_vi : &nic->vi; }
static inline const ef_vi* zf_stack_nic_tx_vi(const zf_stack_nic* nic) {
  return nic->tx_vi.inited ? &nic->tx_vi : &nic->vi; }

static inline ef_vi* zf_stack_nic_tx_vi(zf_stack* st, int nicno) {
  return zf_stack_nic_tx_vi(&st->nic[nicno]); }
static inline const ef_vi* zf_stack_nic_tx_vi(const zf_stack* st, int nicno) {
  return zf_stack_nic_tx_vi(&st->nic[nicno]); }

static inline bool zf_stack_nic_has_tx_vi(const zf_stack* st, int nicno) {
  return st->nic[nicno].tx_vi.inited; }

static inline unsigned* zf_stack_res_nic_flags(zf_stack* st, int nicno) {
  struct zf_stack_impl* sti = ZF_CONTAINER(struct zf_stack_impl, st, st);
  return &sti->nic[nicno].flags;
}

#endif /* __ZF_INTERNAL_STACK_DEF_H__ */

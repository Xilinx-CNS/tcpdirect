/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: Copyright (C) 2024, Advanced Micro Devices, Inc. */


#define __COMPILING_ZF_EMU__

#include <zf_internal/private/zf_hal.h>
#include <zf_internal/attr.h>
#include <zf_internal/utils.h>
#include <zf_internal/checksum.h>
#include <etherfabric/checksum.h>
#include <zf_internal/zf_stack.h>
#include <zf_internal/private/zf_emu.h>
#include <etherfabric/internal/efct_uk_api.h>


#include "zf_emu_superbuf.h"
#include "zf_emu_utils.h"

#include <net/if.h>

#include <sys/mman.h>
#include <sys/stat.h> /* For mode constants */
#include <fcntl.h> /* For O_* constants */
#include <arpa/inet.h>


#ifdef __cplusplus
extern "C" {
#endif

/* ef vi headers */
#include <etherfabric/internal/internal.h>
#include <ci/driver/efab/hardware/host_ef10_common.h>
#include <ci/compat.h>
#include <ci/tools/byteorder.h>
#include <ci/tools/bitfield.h>
#include <ci/driver/efab/hardware/ef10_vaddr.h>
#include <ci/efhw/mc_driver_pcol.h>
#include <ci/efhw/common.h>
#include <ci/net/ipv4.h>

/* x3 headers */
#include <ci/driver/efab/hardware/efct.h>
#define X3_RXQ_N 16
/* Removed from onload in ON-14692 */
#define DP_PARTIAL_TSTAMP_SUB_NANO_BITS EFAB_NIC_DP_DEFAULT(timestamp_subnano_bits)
#define EFCT_TX_APERTURE EFAB_NIC_DP_DEFAULT(tx_aperture_bytes)

#ifdef __cplusplus
}
#endif

/* /dev/onload (for dshm). */
#include <onload/driveraccess.h>

#include <pthread.h>
#include <unistd.h> /* ftruncate */
#include <time.h> /* struct timespec */

/* TUN/TAP headers */
#include <linux/if_tun.h>
#include <sys/ioctl.h>

/* Netlink. */
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>


#include <netinet/ip.h>
#include <netinet/tcp.h>

#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif

static const zf_logger zf_log_emu_err(ZF_LC_EMU, ZF_LL_ERR);
static const zf_logger zf_log_emu_info(ZF_LC_EMU, ZF_LL_INFO);
#ifndef NDEBUG
static const zf_logger zf_log_emu_trace(ZF_LC_EMU, ZF_LL_TRACE);
#else
#define zf_log_emu_trace(...) do{}while(0)
#endif


//TODO REMOVE THIS DEFINE AND FIX IT IN onload bitfield.hs
#define uint64 uint64_t

static const size_t SBUF_SIZE = (size_t)1 << 20;

static int emu_stub_transmit_alt_stop(struct ef_vi* vi, unsigned alt_id)
{
  return ef_vi_transmit_alt_stop(vi, alt_id);
}


static int emu_stub_transmit_alt_go(struct ef_vi* vi, unsigned alt_id)
{
  return ef_vi_transmit_alt_go(vi, alt_id);
}


static int emu_stub_transmit_alt_discard(struct ef_vi* vi, unsigned alt_id)
{
  return ef_vi_transmit_alt_discard(vi, alt_id);
}


static void emu_stub_ef_vi_transmitv_ctpio(ef_vi* vi, size_t frame_len,
                                           const struct iovec* iov, int iovcnt,
                                           unsigned threshold)
{
  ef_vi_transmitv_ctpio(vi, frame_len, iov, iovcnt, threshold);
}


static void emu_stub_ef_vi_transmitv_ctpio_copy(
  ef_vi* vi, size_t frame_len,
  const struct iovec* iov, int iovcnt,
  unsigned threshold, void* fallback)
{
  ef_vi_transmitv_ctpio_copy(vi, frame_len, iov, iovcnt, threshold, fallback);
}


static struct hal_ops_s real_hal_ops = {
  ef_driver_open,
  ef_driver_close,
  ef_pd_alloc,
  ef_vi_alloc_from_pd,
  ef_vi_free,
  ef_pd_free,
  ef_pio_alloc,
  ef_pio_free,
  ef_pio_link_vi,
  ef_pio_unlink_vi,
  ef_memreg_alloc,
  ef_memreg_free,
  ef_vi_get_mac,
  ef_vi_filter_add,
  ef_vi_filter_del,
  oo_cp_create,
  __zf_cplane_get_path,
  oo_fd_open,
  oo_fd_close,
  oo_dshm_register,
  oo_dshm_map,
  oo_dshm_list,
  ef_vi_transmit_alt_alloc,
  ef_vi_transmit_alt_free,
  emu_stub_transmit_alt_stop,
  emu_stub_transmit_alt_go,
  emu_stub_transmit_alt_discard,
  ef_pd_capabilities_get,
  ef_pd_transmit_alt_query_buffering,
  emu_stub_ef_vi_transmitv_ctpio,
  emu_stub_ef_vi_transmitv_ctpio_copy,
  __alloc_huge,
  __free_huge,
};


static const size_t superbuf_size = EFCT_RX_SUPERBUF_BYTES;
static const size_t huge_page_size = CI_HUGEPAGE_SIZE;

static const size_t emu_memreg_size_max = (size_t)CI_TEST_EFCT_MAX_SUPERBUFS *
                                          superbuf_size * (size_t)2;

struct hal_ops_s* hal_ops = &real_hal_ops;

extern struct hal_ops_s emu_hal_ops;

enum vfifo_state { STOP = 0, START, DRAIN };

#define ESE_DZ_TX_OPTION_DESC_VFIFO 2
#define ALT_OP_VFIFO_ID_LBN    48
#define ALT_OP_VFIFO_ID_WIDTH  5
#define ALT_OP_IS_SELECT_LBN   59
#define ALT_OP_IS_SELECT_WIDTH 1

#define VFIFO_DEFAULT 0x1f

#define VFIFO_MAX 17

#define VFIFO_BUFFER_MAX 128

/* With only 5 bits to report the VFIFO ID, and value 0x1f reserved to
 * mean "default", it is not possible to arrange for 17 software IDs
 * and 17 hardware IDs to be completely non-overlapping. 13 is the
 * maximum offset that can be added to the software ID before we run
 * out of hardware ID space. */
#define VFIFO_HW_ID_OFFSET 13

#define SHMNAME_PREFIX "/zf_emu_"
#define SHMADDRNAME_PREFIX "/zf_emu_addr_"

static struct emu_conf {
  int driver_open_count;
  char shmname[IF_NAMESIZE + strlen(SHMNAME_PREFIX) + 1];
  char shmaddrname[IF_NAMESIZE + strlen(SHMADDRNAME_PREFIX) + 1];
  int loop;
  int tun;
  char ifname[IF_NAMESIZE + 1];

  uint32_t vlan_override_addr;
  uint16_t vlan_override_id;
  uint16_t vlan;
  uint16_t mtu;
  /* tap routing state */

  /* ip address of tun interface - typically address of linux stack app */
  uint32_t tunif_addr;
  /* zf stack local address - should be different than tunif_laddr */
  uint32_t local_addr;
  /* both tunif_addr and local_addr should be in the same local network */
  uint32_t tunif_netmask;

  /* destination MAC used for route requests with loopback */
  ci_mac_addr_t dst_mac;

#define NIC_TYPE_HUNTINGTON 0
#define NIC_TYPE_MEDFORD 1
#define NIC_TYPE_MEDFORD2 2
#define NIC_TYPE_X3 3
  int nic_type;
  int tx_nic_type;
  int separate_tx;

  int pio;

  int max_sbufs;
  int fw_variant;
} emu_conf = {
  -1,
  SHMNAME_PREFIX,
  SHMADDRNAME_PREFIX,
};

struct queued_packet {
  struct queued_packet* next;
  void* data;
  size_t len;
};

struct emu_state {
  struct {
    size_t alloced; /* bytes */
    /* offsets from emu_state struct */
    ef_addr dmaaddrs[emu_memreg_size_max/(1u<<EF_VI_NIC_PAGE_SHIFT)];
    /* Used to reset memreg.alloced when emu_state_reset is called */
    size_t alloced_after_init;
  } memreg;

  static const int MAX_VIS = ZF_EMU_MAX_VIS;
  static_stack<size_t, MAX_VIS> vis_free;

  /* x3 state */
  struct emu_stats stats;
  void *superbuf_mapping;

  efhw_nic_efct_rxq rxq;
  static_stack<int, CI_TEST_EFCT_MAX_SUPERBUFS> unused_sbids;
  /* The driver shouldn't be writing to any more than 4 sbufs
   * at a time. */
  static_queue<int, 4> sbids_in_use;
  unsigned sbseq;
  unsigned donated_sbufs;
  CI_BITS_DECLARE(sentinel_sbid, CI_TEST_EFCT_MAX_SUPERBUFS);
  volatile uint32_t buf_ptr alignas(ZF_CACHE_LINE_SIZE);

  /* evis */
  struct emu_vi {
    volatile int alloced;

    /* assume nic per vi */
    char intf_name[IF_NAMESIZE];
    char mac[6];

    int tun_fd;
    int selected_vfifo;
    int nic_type;

    struct vfifo_queue {
      struct queued_packet* first;
      struct queued_packet* last;
    } vfifo[VFIFO_MAX];

    /* This array is written by the zf thread and polled by the shim
     * thread: */
    volatile enum vfifo_state vfifo_state[VFIFO_MAX];

    /* Mock mappings between VI-level IDs and hardware-level IDs */
    unsigned id2hw[VFIFO_MAX];
    unsigned hw2id[VFIFO_MAX + VFIFO_HW_ID_OFFSET];

    uint32_t pftf_pause;
    uint32_t pftf_resume;

    ef_vi_state ep_state;
    ef_vi_stats stats;

    /* Timestamping */
    enum ef_vi_flags flags;
    struct timespec ts_evq;
    struct timespec ts_last_packet;
    struct timespec ts_txq[4096];

    struct emu_dmaq_state {
      /* aligned to cache line size used between threads,
       * avoid bouncing other data from the cache */
      volatile uint32_t ptr alignas(ZF_CACHE_LINE_SIZE);
      /* TODO: ON-13085 */
      volatile uint32_t pkt_ctr alignas(ZF_CACHE_LINE_SIZE);
      uint32_t mask alignas(ZF_CACHE_LINE_SIZE);
#define DMAQ_STATE_FLAG_PHASE_BIT_ON 1
      uint32_t flags;
      uint64_t descriptors[32768];
      uint32_t ids[4096];
      uint32_t superbuf_offset;
      uint32_t superbuf_n;
      uint32_t superbuf_size;
      uint32_t superbuf_total_size;
      uint32_t rx_buffer_len;
      uint32_t superbuf_pkts;
      uint32_t rollover_pkts;
      uint32_t total_buffers;
      struct efab_efct_rxq_uk_shm_base shm;
      /* No extra members here! shm_q is the flexible length array of shm */
      struct efab_efct_rxq_uk_shm_q shm_q[1];
      /* THESE ARE NEEDED FOR X3-userspace */
      uint16_t used_sbid[16];

      struct xlnx_efct_drvops drvops;
      struct xlnx_efct_device edev;
      struct xlnx_efct_client efct_client;
      struct xlnx_efct_rxq_params rxq_params;
      struct efhw_nic_efct nic_efct;
      struct efhw_efct_rxq efct_rxq;

      uint32_t sbid_ctr;
    } evq, txq, rxq;

    union {
      struct {
        union {
          char pad1[4096];
          struct {
            char pad2[ER_DZ_TX_DESC_UPD_REG];
            volatile uint64_t tx_push_desc;
            volatile uint32_t tx_doorbell;
          };
          struct {
            char pad3[ER_DZ_RX_DESC_UPD_REG];
            volatile uint32_t rx_doorbell;
          };
        };
        uint8_t pio[4096];
      } io alignas(ZF_CACHE_LINE_SIZE);

      struct {
        /* here we'll get register layout for tx and rx */
        uint8_t aperture[EFCT_TX_APERTURE];
        uint8_t contiguous[STANDARD_MTU];
      } x3io;
    };

    struct {
      uint8_t buffer[4096];
      uint16_t len;
    } pio alignas(ZF_CACHE_LINE_SIZE);

  } vi[MAX_VIS];
};
#ifdef __cplusplus
typedef emu_state::emu_vi emu_vi;
typedef emu_state::emu_vi::emu_dmaq_state emu_dmaq_state;
typedef emu_state::emu_vi::vfifo_queue vfifo_queue;
#else
typedef struct emu_vi emu_vi;
typedef struct emu_dmaq_state emu_dmaq_state;
typedef struct vfifo_queue vfifo_queue;
#endif


/* This structure describes all of the shared state. */
struct emu_environment {
  bool shm_needs_unlinked;
  bool accept_client;

  /* Most of the functionality provided to ZF by the control plane is shimmed
   * out by the emulator, but we mock up enough cplane state to allow the real
   * cplane implementation to resolve interfaces to ifindices and hwports. */
  struct emu_cplane {
    cp_tables_dim    dim;
    cp_version_t     version;
    cp_version_t     llap_version;
    static const int LLAP_TABLE_SIZE = 32;
    cicp_llap_row_t  llap[LLAP_TABLE_SIZE];
    cicp_rowid_t     llap_free_rowid;
  } cplane_mibs;

  /* points to peer VI - an RX VI if RX and TX VIs are separate */
  int peer_vis[emu_state::MAX_VIS];

  pthread_mutex_t efct_edev_ops_mutex;

  /* State of the emulated hardware. */
  struct emu_state state;

  /* Packet buffers follow the end of this structure: see emu_memreg_start.
   */
};


/* The shared memory segment starts with an [emu_environment] and is followed
 * at the next huge-page boundary by the packet buffers.  [emu_memreg_start] is
 * the offset of the packet buffers from the start of [emu_environment::state],
 * because that's what we need in practice. */
static const size_t emu_memreg_shm_offset = ROUND_UP(sizeof(emu_environment), huge_page_size);
static const size_t emu_memreg_start = (emu_memreg_shm_offset - 
                                        ZF_MEMBER_OFFSET(emu_environment, state));
static const size_t shm_rxqs_size = ROUND_UP(emu_state::MAX_VIS*X3_RXQ_N*sizeof(efhw_nic_efct_rxq), huge_page_size);

static size_t emu_memreg_size() {
  return (size_t)emu_conf.max_sbufs * superbuf_size * (size_t)2;
}

size_t superbuf_mapping_size() {
  return (size_t)emu_conf.max_sbufs * SBUF_SIZE;
}

static size_t shm_len() {
  return emu_memreg_shm_offset + emu_memreg_size() + shm_rxqs_size;
}

/* [emu_client] stores the per-process state.  Multiple processes may be
 * clients of a single emulator, but each process may be a client of at most
 * one emulator. */
static struct {
  /* Each process has at most one mapping of the emulator state. */
  emu_environment* emu_mapping;
  pthread_t thread;
  bool master;
  int driver_handle_count;
  bool emu_shutdown;
  bool request_sync;
} emu_client;


/* Shimmed shm.  Normally the Onload driver manages shared buffers for us, but
 * in the absence of the driver we have to do it ourselves.  The implementation
 * here limits us to 'sharing' buffers within a single process only, but this
 * is enough for testing purposes. */
static struct {
  /* Lists of shared buffers indexed by class. */
  ci_dllist buffers[OO_DSHM_CLASS_COUNT];
  /* In the shim we make no attempt to handle the case where this counter
   * overflows. */
  int next_buffer_id;
} emu_oo_dshm_state;

struct emu_oo_dshm_buffer {
  int buffer_id;
  void* addr;
  size_t length;
  ci_dllink link;
};

static int emu_init(void);

static inline emu_environment* emu_environment_get(void)
{
  if( emu_client.emu_mapping == NULL )
    ZF_TRY(emu_init());
  ZF_TEST(emu_client.emu_mapping != NULL);
  return emu_client.emu_mapping;
}

static inline struct emu_state* emu_state_get(void)
{
  return &emu_environment_get()->state;
}

static inline struct emu_stats& emu_stats_get()
{
  return emu_state_get()->stats;
}

int mock_set_param(struct xlnx_efct_client *handle, enum xlnx_efct_param p, union xlnx_efct_param_value *arg) {
  return 0;
}

void mock_release_superbuf(struct xlnx_efct_client *handle, int rxq, int sbid) {
  emu_state_get()->unused_sbids.push(sbid);
};

int mock_bind_rxq(struct xlnx_efct_client *handle, struct xlnx_efct_rxq_params *params) {
	return 0;
};
int mock_rollover_rxq(struct xlnx_efct_client *handle, int rxq) {
	return 0;
};

void mock_free_rxq(struct xlnx_efct_client *handle, int rxq, size_t n_hugepages) {

};

static void emu_free_rxq(struct efhw_efct_rxq *rxq)
{
}

static int mock_ef_vi_efct_superbuf_refresh(struct ef_vi *vi, int _) {
  return 0;
}

static inline emu_environment* emu_environment_get(void);

static void update_efct_edev_ops(struct efhw_nic_efct *efct)
{
  /* HACK when there are multiple processes, these function pointers can point
   * to the other's address space, thus causing a SEGFAULT */
  emu_vi *evi = (emu_vi*)efct->client->evi;
  evi->rxq.drvops.set_param = mock_set_param;
  evi->rxq.drvops.release_superbuf = mock_release_superbuf;
  evi->rxq.drvops.bind_rxq = mock_bind_rxq;
  evi->rxq.drvops.rollover_rxq = mock_rollover_rxq;
  evi->rxq.drvops.free_rxq = mock_free_rxq;
  evi->rxq.edev.ops = &evi->rxq.drvops;
}

static int safe_efct_poll(void *driver_data, int qid, int budget)
{
  int rc;
  emu_environment* env = emu_environment_get();
  pthread_mutex_lock(&env->efct_edev_ops_mutex);
  struct efhw_nic_efct *efct = (struct efhw_nic_efct *) driver_data;
  update_efct_edev_ops(efct);
  rc = efct_poll(driver_data, qid, budget);
  pthread_mutex_unlock(&env->efct_edev_ops_mutex);
  return rc;
}

static int zf_hal_is_emu(void);


static int emu_incptr_raw(emu_dmaq_state* dq)
{
  ci_wmb();
  return ++dq->ptr;
}


static int emu_ptrinc_raw(emu_dmaq_state* dq)
{
  ci_wmb();
  return dq->ptr++;
}


static int emu_incptr(emu_dmaq_state* dq)
{
  return emu_incptr_raw(dq) & dq->mask;
}


#define TX_COMPLETE_BATCH_SIZE 64


static inline void
txq_pop(emu_state* emu, emu_vi* evi, uint32_t* tx_ptr, uint8_t** txbuf,
        uint32_t* len)
{
  ci_qword_t* txdesc = (ci_qword_t*) &evi->txq.descriptors[*tx_ptr];
  /* get len and address of the tx buffer to copy from */
  int pio = CI_QWORD_FIELD64(*txdesc, ESF_DZ_TX_PIO_TYPE);
  if( pio ) {
    /* This could be either a PIO or an option descriptor */
    int opt_type = CI_QWORD_FIELD64(*txdesc, ESF_DZ_TX_OPTION_TYPE);
    if( opt_type == ESE_DZ_TX_OPTION_DESC_VFIFO ) {
      if( CI_QWORD_FIELD64(*txdesc, ALT_OP_IS_SELECT) != 0 ) {
        evi->selected_vfifo = CI_QWORD_FIELD64(*txdesc, ALT_OP_VFIFO_ID);
      }
      *len = 0;
      *txbuf = NULL;
    }
    else {
      uint64_t buf_addr = CI_QWORD_FIELD64(*txdesc, ESF_DZ_TX_PIO_BUF_ADDR);
      *len = CI_QWORD_FIELD64(*txdesc, ESF_DZ_TX_PIO_BYTE_CNT);
      *txbuf = evi->io.pio + buf_addr;
    }
  }
  else {
    uint64_t bus_addr =
        CI_QWORD_FIELD64(*txdesc, ESF_DZ_TX_KER_BUF_ADDR);
    *len = CI_QWORD_FIELD64(*txdesc,ESF_DZ_TX_KER_BYTE_CNT);
    int cont = CI_QWORD_FIELD64(*txdesc, ESF_DZ_TX_KER_CONT);
    ZF_TEST(cont == 0);
    ZF_TEST(bus_addr < emu_memreg_size());
    *txbuf = (uint8_t*) emu + emu_memreg_start + bus_addr;
  }
  *tx_ptr = emu_incptr(&evi->txq);
}


static inline void
rxq_pop(emu_state* emu, emu_vi* evi, uint32_t* rx_ptr, uint8_t** rxbuf,
        uint32_t* len)
{

  ci_qword_t* desc = (ci_qword_t*) &evi->rxq.descriptors[*rx_ptr];
  uint64_t bus_addr =
      CI_QWORD_FIELD64(*desc, ESF_DZ_RX_USR_BUF_ID_OFFSET) +
      (CI_QWORD_FIELD64(*desc, ESF_DZ_RX_USR_BUF_PAGE_SIZE) <<
       EF10_BUF_VADDR_ORDER_SHIFT);
  uint32_t rx_len = CI_QWORD_FIELD64(*desc, ESF_DZ_RX_USR_BYTE_CNT);
  ZF_TEST(bus_addr < emu_memreg_size());
  *len = rx_len;
  *rxbuf = (uint8_t*) emu + emu_memreg_start + bus_addr;

  *rx_ptr = emu_incptr(&evi->rxq);
}


#define NSEC_PER_SEC   1000000000L
#define NSEC_PER_MSEC  1000000L
static inline int64_t timespec_to_ns(const struct timespec *ts)
{
  return ((int64_t) ts->tv_sec * NSEC_PER_SEC) + ts->tv_nsec;
}


#include <tuple>

#define MCDI_EVENT_PHASE_BIT_LBN 55
#define MCDI_EVENT_PHASE_BIT_WIDTH 1

ci_qword_t* evq_next_desc(emu_dmaq_state* dq)
{
  return (ci_qword_t*) &dq->descriptors[dq->ptr & dq->mask];
}

bool evq_next_phase(emu_dmaq_state* dq)
{
  return (dq->ptr & (dq->mask + 1)) &&
         (dq->flags & DMAQ_STATE_FLAG_PHASE_BIT_ON);
}

static inline void
evq_maybe_tsync_x3(emu_vi* evi, const struct timespec* ts_now)
{
  auto tsync_seconds = (ts_now->tv_sec & 0xFFFFFFFF) << 16;
  auto tsync_nanos = (ts_now->tv_nsec >> 14) & 0xFFFF;
  auto time_high = (tsync_seconds | tsync_nanos);
  CI_POPULATE_QWORD_7(*evq_next_desc(&evi->evq),
          EFCT_TX_EVENT_LABEL, 0,
          EFCT_EVENT_TYPE, EFCT_EVENT_TYPE_CONTROL,
          EFCT_CTRL_SUBTYPE, EFCT_CTRL_EV_TIME_SYNC,
          EFCT_TIME_SYNC_EVENT_TIME_HIGH, time_high,
          EFCT_TIME_SYNC_EVENT_CLOCK_IN_SYNC, 1,
          EFCT_TIME_SYNC_EVENT_CLOCK_IS_SET, 1,
          EFCT_EVENT_PHASE, evq_next_phase(&evi->evq));
  emu_ptrinc_raw(&evi->evq);
}

static inline void
evq_maybe_tsync_ef10(emu_vi* evi, const struct timespec* ts_now)
{
  uint64_t timesync_minor = (ts_now->tv_nsec << 27) / 1000000000;
  uint64_t timesync_major = ts_now->tv_sec;

  CI_POPULATE_QWORD_6(*evq_next_desc(&evi->evq),
              ESF_DZ_EV_CODE, ESE_DZ_EV_CODE_MCDI_EV,
              MCDI_EVENT_CODE, MCDI_EVENT_CODE_PTP_TIME,
              MCDI_EVENT_PTP_TIME_MINOR_26_21, (timesync_minor >> 21),
              MCDI_EVENT_PTP_TIME_MAJOR, timesync_major,
              MCDI_EVENT_PTP_TIME_HOST_NIC_IN_SYNC, 1,
              MCDI_EVENT_PTP_TIME_NIC_CLOCK_VALID, 1);
  emu_ptrinc_raw(&evi->evq);
}

static inline void
evq_maybe_tsync(emu_vi* evi, const struct timespec* ts_now)
{
  int64_t ts_diff = timespec_to_ns(ts_now) - timespec_to_ns(&evi->ts_evq);

  if( ts_diff > NSEC_PER_MSEC * 250 ) {
    zf_log_emu_info(NO_STACK,
                    "TSync VI %d %ld.%ld\n", evi - emu_client.emu_mapping->state.vi,
                    ts_now->tv_sec, ts_now->tv_nsec);

    if ( evi->nic_type == NIC_TYPE_X3 ) {
      evq_maybe_tsync_x3(evi, ts_now);
    } else {
      evq_maybe_tsync_ef10(evi, ts_now);
    }

    evi->ts_evq = *ts_now;
  }
}

static inline void
evq_push_rx(emu_vi* evi, uint32_t rx_ptr, uint32_t len)
{
  evq_maybe_tsync(evi, &evi->ts_last_packet);

  CI_POPULATE_QWORD_6(*evq_next_desc(&evi->evq),
              ESF_DZ_EV_CODE, ESE_DZ_EV_CODE_RX_EV,
              ESF_DZ_RX_DSC_PTR_LBITS,
              (rx_ptr) & ((1 << ESF_DZ_RX_DSC_PTR_LBITS_WIDTH) - 1),
              ESF_DZ_RX_BYTES, len,
              ESF_DZ_RX_CONT, 0,
              ESF_DZ_RX_MAC_CLASS, ESE_DZ_MAC_CLASS_UCAST,
              MCDI_EVENT_PHASE_BIT, evq_next_phase(&evi->evq));
  emu_ptrinc_raw(&evi->evq);
}

static inline void
evq_push_tx_x3(emu_vi* evi)
{
  CI_POPULATE_QWORD_4(*evq_next_desc(&evi->evq),
              EFCT_TX_EVENT_LABEL, 0,
              EFCT_TX_EVENT_SEQUENCE, evi->txq.pkt_ctr & ((1 << EFCT_TX_EVENT_SEQUENCE_WIDTH) - 1),
              EFCT_EVENT_TYPE, EFCT_EVENT_TYPE_TX,
              EFCT_EVENT_PHASE, evq_next_phase(&evi->evq));
  emu_ptrinc_raw(&evi->evq);
}

static inline void
evq_push_tx_ef10(emu_vi* evi, uint32_t tx_ptr)
{
  CI_POPULATE_QWORD_3(*evq_next_desc(&evi->evq),
              ESF_DZ_EV_CODE, ESE_DZ_EV_CODE_TX_EV,
              ESF_EZ_TX_SOFT1, TX_TIMESTAMP_EVENT_TX_EV_COMPLETION,
              ESF_DZ_TX_DESCR_INDX, (tx_ptr - 1) & evi->txq.mask);
  emu_ptrinc_raw(&evi->evq);
}

static inline void
evq_push_tx(emu_vi* evi, uint32_t tx_ptr=0)
{
  if ( evi->nic_type == NIC_TYPE_X3 ) {
    evq_push_tx_x3(evi);
  } else {
    evq_push_tx_ef10(evi, tx_ptr);
  }
}

static inline void
evq_push_tx_ts_x3(emu_vi* evi)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  auto partial_tstamp_seconds = (ts.tv_sec & 0xFF) << 32;
  auto partial_tstamp_nanos = (ts.tv_nsec & 0x7FFFFFFF) << DP_PARTIAL_TSTAMP_SUB_NANO_BITS;
  auto ptstamp = partial_tstamp_seconds | partial_tstamp_nanos;
  CI_POPULATE_QWORD_6(*evq_next_desc(&evi->evq),
              EFCT_TX_EVENT_LABEL, 0,
              EFCT_TX_EVENT_SEQUENCE, evi->txq.pkt_ctr & ((1 << EFCT_TX_EVENT_SEQUENCE_WIDTH) - 1),
              EFCT_EVENT_TYPE, EF_EVENT_TYPE_TX,
              EFCT_TX_EVENT_TIMESTAMP_STATUS, 1,
              EFCT_TX_EVENT_PARTIAL_TSTAMP, ptstamp,
              EFCT_EVENT_PHASE, evq_next_phase(&evi->evq));
  emu_ptrinc_raw(&evi->evq);
}

static inline void
evq_push_tx_ts_ef10(emu_vi* evi, uint32_t tx_ptr)
{
  CI_POPULATE_QWORD_3(*evq_next_desc(&evi->evq),
              ESF_DZ_EV_CODE, ESE_DZ_EV_CODE_TX_EV,
              ESF_EZ_TX_SOFT1, TX_TIMESTAMP_EVENT_TX_EV_COMPLETION,
              ESF_DZ_TX_DESCR_INDX, tx_ptr);
  emu_ptrinc_raw(&evi->evq);

  uint32_t lo = ((uint64_t)evi->ts_txq[tx_ptr].tv_nsec << 27) / 1000000000;
  CI_POPULATE_QWORD_4(*evq_next_desc(&evi->evq),
              ESF_DZ_EV_CODE, ESE_DZ_EV_CODE_TX_EV,
              ESF_EZ_TX_SOFT1, TX_TIMESTAMP_EVENT_TX_EV_TSTAMP_LO,
              ESF_DZ_TX_SOFT2, lo >> 16,
              ESF_DZ_TX_DESCR_INDX, lo & 0xffff);
  emu_ptrinc_raw(&evi->evq);

  CI_POPULATE_QWORD_3(*evq_next_desc(&evi->evq),
              ESF_DZ_EV_CODE, ESE_DZ_EV_CODE_TX_EV,
              ESF_EZ_TX_SOFT1, TX_TIMESTAMP_EVENT_TX_EV_TSTAMP_HI,
              ESF_DZ_TX_DESCR_INDX, evi->ts_txq[tx_ptr].tv_sec & 0xffff);
  emu_ptrinc_raw(&evi->evq);
}

static inline void
evq_push_tx_ts(emu_vi* evi, uint32_t tx_ptr=0)
{
  if( ! evi->ts_last_packet.tv_sec ) {
    /* This is for TX-only VI */
    struct timespec transmit_time;
    clock_gettime(CLOCK_MONOTONIC, &transmit_time);
    evq_maybe_tsync(evi, &transmit_time);
  }
  if ( evi->nic_type == NIC_TYPE_X3 ) {
    evq_push_tx_ts_x3(evi);
  } else {
    evq_push_tx_ts_ef10(evi, tx_ptr);
  }
}


static inline void
evq_push_tx_alt(emu_vi* evi, uint32_t alt_id)
{
  CI_POPULATE_QWORD_3(*evq_next_desc(&evi->evq),
              ESF_DZ_EV_CODE, ESE_DZ_EV_CODE_TX_EV,
              ESF_EZ_TX_SOFT1, TX_TIMESTAMP_EVENT_TX_EV_TSTAMP_HI,
              ESF_DZ_TX_SOFT2, evi->id2hw[alt_id]);
  emu_ptrinc_raw(&evi->evq);
}

static void populate_prefix(emu_vi *evi, char *txbuf)
{
#define FLAG_NO_TIMESTAMP   0x80000000

  struct timespec transmit_time;
  clock_gettime(CLOCK_MONOTONIC, &transmit_time);
  evi->ts_last_packet = transmit_time;

  uint32_t pkt_minor =
    (uint32_t)(((uint64_t) transmit_time.tv_nsec << 27) / 1000000000);
  pkt_minor &= ~FLAG_NO_TIMESTAMP;

  memcpy(txbuf, "PFPFPFPFPFPFPF", 14); // mark the prefix area for debug
  *(uint32_t*)(txbuf + ES_DZ_RX_PREFIX_TSTAMP_OFST) = pkt_minor;
}

void nic_buffer_copy(volatile void* dst, const void* src) {
  volatile uint64_t* d = (volatile uint64_t*) dst;
  const uint64_t* s = (const uint64_t*) src;
  zf_assume_equal((intptr_t) d & (NIC_RX_BUFFER_WRITE_SIZE - 1), 0);
  for(size_t i = 0 ; i < NIC_RX_BUFFER_WRITE_SIZE / sizeof(*d); ++i)
    d[i] = s[i];
}

/* Packets-from-the-future requires that cache lines appear in order, and that
 * the presence of the first dword in a cache line implies the presence of the
 * rest of that cache line.
 * Overlapped receive logic in TCPDirect rely on NIC property to fill up the 
 * buffer to the end of 64-byte NIC write block, specifically to write the
 * last qword in that block.
 * Below the NIC behaviour is replicated to satisfy TCPDirect.
 */
static void* packet_memcpy(emu_vi* evi, void *pkt_dest, const void *src,
                           size_t n)
{
  void* orig_dest = pkt_dest;

  /* Verify that only pkts with appropriate vlan headers are emited */
  if( emu_conf.vlan_override_addr )
   ;
  else if( emu_conf.vlan == ZF_NO_VLAN ) {
    zf_assert_equal(((ethhdr*)src)->h_proto, zf_htons(ETH_P_IP));
  }
  else {
    zf_assert_equal(((ethhdr*)src)->h_proto, zf_htons(ETH_P_8021Q));
    zf_assert_equal(((ethhdr*)((char*)src + 4))->h_proto, zf_htons(ETH_P_IP));
  }

  /* ES_DZ_RX_PREFIX_SIZE already added to n */
  int final_n = ROUND_UP(n, NIC_RX_BUFFER_WRITE_SIZE);
  char txbuf[final_n] alignas(ZF_CACHE_LINE_SIZE);
  if( evi->flags & EF_VI_RX_TIMESTAMPS ) {
    memcpy(txbuf + ES_DZ_RX_PREFIX_SIZE, src, n - ES_DZ_RX_PREFIX_SIZE);
    populate_prefix(evi, txbuf);
  }
  else {
    memcpy(txbuf, src, n);
  }
  src = txbuf;

  /* Fill up to NIC_RX_BUFFER_WRITE_SIZE as NIC does */
  memset(txbuf + n, 'F', final_n - n);
  n = final_n;

  /* Copy the first block avoiding the poison dword at the beginning.
   * Further nic_buffer_copy will overwrite it atomically
   * Among other this will ensure zfr_packet_header_present debug
   * assertion does not fire */
  __builtin_memcpy((uint64_t*)pkt_dest + 1, (const uint64_t*) txbuf + 1,
                   NIC_RX_BUFFER_WRITE_SIZE - sizeof(uint64_t));

  ci_wmb();

  int first = 1;

  while( n > 0 ) {
    /* Write up to one cache line per iteration. */
    size_t this_n = NIC_RX_BUFFER_WRITE_SIZE;


    if( first ) {
      /* For first cache line just fill the POISON word,
       * note that tcpdirect uses first 10 bytes of rx prefix for
       * storage after detecting poison */
      *(volatile uint64_t*)pkt_dest = *(const uint64_t*) txbuf;
      first = 0;
    } else {
      nic_buffer_copy(pkt_dest, src);
    }

    pkt_dest = (char*) pkt_dest + this_n;
    src = (char*) src + this_n;
    n -= this_n;

    ci_wmb();
  }

  return orig_dest;
}

static void emu_pftf_wait(emu_vi* evi)
{
  auto pause = OO_ACCESS_ONCE(evi->pftf_pause);
  while( pause != OO_ACCESS_ONCE(evi->pftf_resume) )
    sched_yield();
}


static void emu_deliver_ef10(emu_state* emu, emu_vi* evi,
                        const void* txbuf, size_t len)
{
  uint32_t rx_db = evi->io.rx_doorbell & evi->rxq.mask;

  /* get len and address of the other's vi rx buffer to copy to */
  uint32_t rx_ptr = evi->rxq.ptr & evi->rxq.mask;

  ci_rmb();

  if( rx_ptr == rx_db ) {
    zf_log_emu_info(NO_STACK, "Rx ring empty - dropping packet\n");
    return;
  }

  uint8_t* rxbuf;
  uint32_t rxlen;
  rxq_pop(emu, evi, &rx_ptr, &rxbuf, &rxlen);

  bool rx_ts = evi->flags & EF_VI_RX_TIMESTAMPS;
  if( rx_ts )
    len += ES_DZ_RX_PREFIX_SIZE;

  ZF_TEST(len <= rxlen);

  /* copy data */
  packet_memcpy(evi, rxbuf, txbuf, len);

  emu_pftf_wait(evi);

  /* issue rx notification on evi */
  evq_push_rx(evi, rx_ptr, len);
}


static ci_oword_t efct_rx_metadata(unsigned length, unsigned next_frame_loc,
                                 unsigned csum_frame, unsigned l2_class,
                                 unsigned l3_class, unsigned l4_class,
                                 unsigned l2_status, unsigned l3_status,
                                 unsigned l4_status, unsigned rollover,
                                 unsigned sentinel, unsigned timestamp_status,
                                 uint64_t timestamp, unsigned user)
{
  ci_oword_t oword1, oword2;

  CI_POPULATE_OWORD_7(oword1,
    EFCT_RX_HEADER_PACKET_LENGTH,    length,
    EFCT_RX_HEADER_NEXT_FRAME_LOC,   next_frame_loc,
    EFCT_RX_HEADER_CSUM,             csum_frame,
    EFCT_RX_HEADER_L2_CLASS,         l2_class,
    EFCT_RX_HEADER_L3_CLASS,         l3_class,
    EFCT_RX_HEADER_L4_CLASS,         l4_class,
    EFCT_RX_HEADER_L2_STATUS,        l2_status);
  CI_POPULATE_OWORD_7(oword2,
    EFCT_RX_HEADER_L3_STATUS,        l3_status,
    EFCT_RX_HEADER_L4_STATUS,        l4_status,
    EFCT_RX_HEADER_ROLLOVER,         rollover,
    EFCT_RX_HEADER_SENTINEL,         sentinel,
    EFCT_RX_HEADER_TIMESTAMP_STATUS, timestamp_status,
    EFCT_RX_HEADER_TIMESTAMP,        timestamp,
    EFCT_RX_HEADER_USER, user
  );
  oword1.u64[0] |= oword2.u64[0];
  oword1.u64[1] |= oword2.u64[1];
  return oword1;
}

static bool buffers_are_available(emu_vi* evi){
  /* TODO do the invalidation with just two counters */
  /* Check difference between added-removed and compare with buffer_capacity */
  if ( evi->nic_type == NIC_TYPE_X3 ) {
    return !emu_state_get()->sbids_in_use.empty();
  } else {
    return true;
  }
}


static char* get_superbuf(emu_vi* evi, uint16_t sbid) {
  char* env = (char*)emu_client.emu_mapping;
  return env + evi->rxq.superbuf_offset + sbid * evi->rxq.superbuf_size;
}


static uint32_t get_packet_count(emu_state* emu, emu_vi *evi)
{
  return emu->buf_ptr / evi->rxq.rx_buffer_len;
}


static uint16_t get_currently_active_superbuf(emu_vi* evi)
{
  return emu_state_get()->sbids_in_use.front();
}

static void superbuf_end(emu_vi* evi, int sbid, bool force)
{
  int rxq_id = 0;
  emu_stats_get().sbufs[sbid].n_ends++;
  if ( efct_buffer_end((void*) &evi->rxq.nic_efct, rxq_id, sbid, force) == 1 ) {
    evi->rxq.drvops.release_superbuf(&evi->rxq.efct_client, rxq_id, sbid);
  }
}


static void poison_superbuf(emu_vi* evi, int sbid)
{
  uint64_t poison = (uint64_t)RX_PACKET_POISON_HEADER << 16;
  char* base = get_superbuf(evi, sbid);
  for( unsigned i = 0; i < evi->rxq.superbuf_pkts; ++i ) {
    memcpy(base + ZF_CACHE_LINE_SIZE, &poison, sizeof(poison));
    base += evi->rxq.rx_buffer_len;
  }
}


static int _get_sentinel_x3(emu_vi* evi)
{
  return !(ci_bit_test(emu_state_get()->sentinel_sbid, 
           get_currently_active_superbuf(evi)));
}

static int get_sentinel(emu_vi* evi)
{
  return _get_sentinel_x3(evi);
}

static void bit_xor(volatile ci_bits* b, int i) {
  if(ci_bit_test(b, i)) {
    __ci_bit_clear(b, i);
  } else {
    __ci_bit_set(b, i);
  }
}


static void finished_with_current_sbuf(emu_state *state, emu_vi* evi){
  superbuf_end(evi, state->sbids_in_use.deq(), false);      
}


char *get_rxbuf(emu_state *emu, emu_vi *evi) {
  return get_superbuf(evi, get_currently_active_superbuf(evi)) +
    + emu->buf_ptr % evi->rxq.superbuf_size;
}


static void curr_sbuf_rollover(emu_state *emu, emu_vi *evi) {
  emu_stats_get().sbufs[get_currently_active_superbuf(evi)].n_rollovers++;

  auto rxbuf = [&evi, &emu]{
      return get_rxbuf(emu, evi);
  };
  auto advance_buf_ptr = [&emu, &evi] {
    emu->buf_ptr += evi->rxq.rx_buffer_len;
  };

  int sentinel = get_sentinel(evi);
  /* Write rollover metadata */
  auto prefix = efct_rx_metadata(0, 1, 0, 0, 2, 3, 2, 1, 1, 1, sentinel, 0, 0, 0);
  emu->buf_ptr += evi->rxq.rx_buffer_len - EFCT_RX_HEADER_NEXT_FRAME_LOC_1;
  __builtin_memcpy(rxbuf(), &prefix, sizeof(prefix));
  advance_buf_ptr();

  /* Fill rest of metadata in sbuf with dummy metadata data. */
  prefix = efct_rx_metadata(0, 1, 0, 0, 0, 0, 0, 0, 0, 0, sentinel, 0, 0, 0);
  while( get_packet_count(emu, evi) % evi->rxq.superbuf_pkts != 0 ) {
    __builtin_memcpy(rxbuf(), &prefix, sizeof(prefix));
    advance_buf_ptr();
  }
  finished_with_current_sbuf(emu, evi);
  /* Write dummy metadata to the next sbuf as the previous packet in the
   * previous superbuf will be empty. We have moved to a new sbuf -
   * use the sentinel of that sbuf. */
  prefix = efct_rx_metadata(0, 1, 0, 0, 0, 0, 0, 0, 0, 0, get_sentinel(evi), 0, 0, 0);
  __builtin_memcpy(rxbuf(), &prefix, sizeof(prefix));
  emu->buf_ptr += EFCT_RX_HEADER_NEXT_FRAME_LOC_1;
}


static unsigned get_donated_sbufs(struct emu_state *state) {
  return state->donated_sbufs ? CI_MAX(state->donated_sbufs + 2, 4) : 0;
}


static void superbuf_begin(emu_state *state, emu_vi* evi) {
  auto &unused_sbids = state->unused_sbids;
  if(!unused_sbids.empty()) {

    if(CI_TEST_EFCT_MAX_SUPERBUFS - state->unused_sbids.size() >=
       (size_t) get_donated_sbufs(state)) {
      return;
    }

    if(state->sbids_in_use.full()) {
      curr_sbuf_rollover(state, evi);
    }

    int sbid = unused_sbids.pop();

    bool sentinel = ci_bit_test(state->sentinel_sbid, sbid) > 0;
    int qid = 0;
    poison_superbuf(evi, sbid);
    if ( efct_buffer_start((void*) &evi->rxq.nic_efct, qid, state->sbseq, sbid, sentinel) == 1 ) {
      bit_xor(state->sentinel_sbid, sbid);
      state->sbids_in_use.enq(sbid);
      state->sbseq++;
      emu_stats_get().sbufs[sbid].n_starts++;
    }
  }
}


static void emu_deliver_x3(emu_state* emu, emu_vi* evi,
                        const void* txbuf, size_t pkt_len)
{
  if ( !buffers_are_available(evi) ) {
    emu_stats_get().no_desc_drops += pkt_len;
    return;
  }

  auto rxbuf = [&evi, &emu]{
      return get_rxbuf(emu, evi);
  };

  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  uint64_t timestamp = (ts.tv_sec << 32) | (ts.tv_nsec << 2);

  uint64_t poisoned = 0;
  __builtin_memcpy((char*)&poisoned + 2, txbuf, 6);
  char* dst = rxbuf();
  if( pkt_len > 6 )
    __builtin_memcpy(dst + 6, (char*)txbuf + 6, pkt_len - 6);
  *(volatile uint64_t*)(dst - 2) = poisoned;

  emu->buf_ptr += evi->rxq.rx_buffer_len - EFCT_RX_HEADER_NEXT_FRAME_LOC_1;

  auto pkt_count = get_packet_count(emu, evi);
  if( pkt_count % evi->rxq.superbuf_pkts == 0 ) {
    /* The metadata will be written in the next sbuf so we finish with the 
     * current one. */
    finished_with_current_sbuf(emu, evi);
  }

  int sentinel = get_sentinel(evi);
  auto prefix = efct_rx_metadata(pkt_len, 1, 0, 0, 0, 0, 0, 0, 0, 0, sentinel,
                                 1, timestamp, 0);

  zf_assert_equal(emu->buf_ptr % evi->rxq.rx_buffer_len, 0);

  __builtin_memcpy(rxbuf(), &prefix, sizeof(prefix));
  emu->buf_ptr += EFCT_RX_HEADER_NEXT_FRAME_LOC_1;
  if( pkt_count % evi->rxq.superbuf_pkts == 0 ) {
    superbuf_begin(emu, evi);
  }
}

static void emu_deliver(emu_state* emu, emu_vi* evi,
                        const void* txbuf, size_t len)
{

  if( evi->nic_type == NIC_TYPE_X3 ) {
    emu_deliver_x3(emu, evi, txbuf, len);
  } else {
    emu_deliver_ef10(emu, evi, txbuf, len);
  }
}


static void emu_deliver_queue(emu_state* emu, emu_vi* evi, 
                              emu_vi* txvi, unsigned txid, 
                              vfifo_queue* vq, bool deliver)
{
  ZF_TEST( vq->first != NULL );
  ZF_TEST( vq->last != NULL );

  while( vq->first != NULL ) {
    struct queued_packet* pkt = vq->first;

    vq->first = pkt->next;

    if( deliver ) {
      emu_deliver(emu, evi, pkt->data, pkt->len);
    }

    evq_push_tx_alt(txvi, txid);

    free(pkt->data);
    free(pkt);
  }

  ZF_TEST( vq->first == NULL );
  vq->last = NULL;
}


static void emu_queue_packet(vfifo_queue* vq, const void* data, size_t len)
{
  struct queued_packet* qp;

  qp = (struct queued_packet*) malloc(sizeof(*qp));
  if( !qp ) {
    zf_log_emu_info(NO_STACK, "Dropped packet: out of memory\n");
    return;
  }

  qp->data = malloc(len);
  if( !qp->data ) {
    zf_log_emu_info(NO_STACK, "Dropped packet: out of memory\n");
    free(qp);
    return;
  }

  qp->len = len;
  memcpy(qp->data, data, len);
  qp->next = NULL;

  if( vq->last )
    vq->last->next = qp;
  else
    vq->first = qp;
  vq->last = qp;
}


static void tun_write_packet(int tun_fd, uint8_t* txbuf, uint32_t len,
                             uint32_t ethhdr_size)
{
  /* Add IP and protocol checksums */
  struct iphdr* iph = (struct iphdr*) (txbuf + ethhdr_size);
  iph->check = ef_ip_checksum(iph);
  if( iph->protocol == IPPROTO_TCP ) {
    struct tcphdr* tcph = (struct tcphdr*) ((uint8_t*) iph + (iph->ihl * 4));
    tcph->check = zf_tcp_checksum(iph, tcph,
                                  ((uint8_t*) tcph) + (tcph->doff * 4));
  }
  /* Don't need to bother with UDP checksum - it's optional and zf
   * initialises the checksum field to 0 */
  ZF_TRY(write(tun_fd, txbuf + ethhdr_size, len - ethhdr_size));
}

extern __attribute__((weak)) ssize_t zfss_sys_read(int fd, void* buf, size_t);

static void tun_read_packet(int tun_fd, emu_state* emu, emu_vi* evi,
                            uint32_t ethhdr_size)
{
  char tbuf[2048];
  char rxbuf_intermediate[2048];
  int rc = (zfss_sys_read ? zfss_sys_read : read)(tun_fd, tbuf, sizeof(tbuf));
  if( rc < 0 && errno == EAGAIN )
    return;
  ZF_TRY(rc);
  if( rc > emu_conf.mtu ) {
    ZF_ONCE(
            zf_log_emu_err(NO_STACK,
                           "Warning: Pkt of size (%d) > MTU(%d) received from "
                           "TUN dev\n", rc, emu_conf.mtu) );
    /* strictly MTU does not limit packet size on rx, but might indicate
     * MSS negotiation failure ... or a stray packet from OS */
  }

  /* TODO: if rx is underflowed we should drop the packet */

  /* Stage an Ethernet header in an intermediate buffer. */
  struct ethhdr* eh = (struct ethhdr*) rxbuf_intermediate;
  memcpy(eh->h_dest, evi->mac, sizeof(evi->mac));
  memcpy(eh->h_source, evi->mac, sizeof(evi->mac));
  eh->h_proto = zf_htons(ETH_P_IP);

  /* Copy the packet data after the Ethernet header. */
  memcpy(rxbuf_intermediate + ethhdr_size, tbuf, rc);

  emu_deliver(emu, evi, rxbuf_intermediate, rc + ethhdr_size);
}

static void zf_emu_update_tsync(emu_environment* env)
{
  struct emu_state* emu = &env->state;
  for( int vi_no = 0; vi_no < emu->MAX_VIS; ++vi_no ) {
    emu_vi* tx_evi = &emu->vi[vi_no];
    if( ! tx_evi->alloced )
      continue;

    emu_vi* rx_evi = &emu->vi[env->peer_vis[vi_no]];
    if( ! (rx_evi && rx_evi->alloced) )
      continue;

    struct timespec ts_now;
    clock_gettime(CLOCK_MONOTONIC, &ts_now);
    if( tx_evi != rx_evi )
      evq_maybe_tsync(tx_evi, &ts_now);
    evq_maybe_tsync(rx_evi, &ts_now);
  }
}

static void decode_efct_tx_header(ci_qword_t* desc, efct_tx_ctpio_header* header)
{
    header->packet_length      = CI_QWORD_FIELD(*desc, EFCT_TX_HEADER_PACKET_LENGTH);
    header->ct_thresh          = CI_QWORD_FIELD(*desc, EFCT_TX_HEADER_CT_THRESH);
    header->timestamp_flag     = CI_QWORD_FIELD(*desc, EFCT_TX_HEADER_TIMESTAMP_FLAG);
    header->warm_flag          = CI_QWORD_FIELD(*desc, EFCT_TX_HEADER_WARM_FLAG);
    header->action             = CI_QWORD_FIELD(*desc, EFCT_TX_HEADER_ACTION);
}

static void zf_emu_poll_x3(emu_vi* tx_evi, emu_vi* rx_evi, int tun_fd, const uint32_t ethhdr_size, struct emu_state* emu, int vi_no)
{
  /* scan aperture, decode headers, copy packets, */
  /* follow through to generating events */
  /* first detect the presence of the header 
    to do this, scan the aperture and check if it isn't
    FFFFs. If true, decode the header...*/
  int qid = 0;
  int budget = 0; //not used anyway?
  /* By the time we reach this function, `tx_evi` is guaranteed to be valid.
   * If we have a separate `rx_evi`, such as if we have specifically requested
   * this with `force_separate_tx_vi`, then we should poll that one instead. */
  emu_vi *evi = rx_evi ? rx_evi : tx_evi;
  safe_efct_poll((void*) &evi->rxq.nic_efct, qid, budget);

  ci_qword_t* header_ptr = (ci_qword_t*) &tx_evi->x3io.aperture[tx_evi->txq.ptr % EFCT_TX_APERTURE];
  if ( !CI_QWORD_IS_ALL_ONES( *header_ptr ) ) {
    struct efct_tx_ctpio_header header;
    decode_efct_tx_header( header_ptr, &header );

    uint32_t total_length = ROUND_UP(header.packet_length + EFCT_TX_HEADER_BYTES, EFCT_TX_ALIGNMENT);

    /*  if the last qword is all ones, this means that the 
        client has not written all the packet data yet.
    */

    ci_qword_t* last_word = (ci_qword_t*) &tx_evi->x3io.aperture[(tx_evi->txq.ptr + total_length - sizeof(ci_qword_t)) % EFCT_TX_APERTURE];
    if( CI_QWORD_IS_ALL_ONES( *last_word ) ) {
      return;
    }

    uint8_t* txbuf = (uint8_t*) header_ptr + EFCT_TX_HEADER_BYTES;
    unsigned rem = EFCT_TX_APERTURE - ((uintptr_t) txbuf - (uintptr_t) &tx_evi->x3io.aperture);

    if ( header.packet_length > rem ) {
      // coalesce from txbuf into contiguous buffer 
      __builtin_memcpy(&tx_evi->x3io.contiguous, txbuf, rem);
      __builtin_memcpy(&tx_evi->x3io.contiguous[rem], &tx_evi->x3io.aperture, header.packet_length - rem);
      txbuf = (uint8_t*) &tx_evi->x3io.contiguous;
    }

    if( tun_fd >= 0 ) {
        /* Write the packet to the TUN device. */
      tun_write_packet(tun_fd, txbuf, header.packet_length, ethhdr_size);
    } else {
      /* Copy the packet into a RX buffer on the RX VI, and write an RX
      * event. */
      zf_assert(rx_evi);
      emu_deliver(emu, rx_evi, txbuf, header.packet_length);
    }

    rem += EFCT_TX_HEADER_BYTES;
    if ( total_length > rem ) {
      memset(header_ptr, 0xFF, rem);
      memset(&tx_evi->x3io.aperture, 0xFF, total_length - rem);
    } else {
      memset(header_ptr, 0xFF, total_length);
    }

    if( tx_evi->flags & EF_VI_TX_TIMESTAMPS ) {
      evq_push_tx_ts(tx_evi);
    } else {
      evq_push_tx(tx_evi);
    }

    tx_evi->txq.ptr += total_length;
    tx_evi->txq.pkt_ctr += 1;
  }
}

static void zf_emu_poll_ef10(emu_vi* tx_evi, emu_vi* rx_evi, int tun_fd, const uint32_t ethhdr_size, struct emu_state* emu, int vi_no)
{
  uint32_t tx_db = tx_evi->io.tx_doorbell & tx_evi->txq.mask;
  uint32_t tx_ptr = tx_evi->txq.ptr & tx_evi->txq.mask;
  uint32_t previous_tx_ptr = tx_ptr;
  uint32_t tx_ptr_batch_limit = (tx_ptr + TX_COMPLETE_BATCH_SIZE) &
                                tx_evi->txq.mask;

  /* Process descriptors from the queue until the queue runs dry or until we
  * reach the batch-limit. */
  while( tx_ptr != tx_db && tx_ptr != tx_ptr_batch_limit ) {
    uint8_t* txbuf;
    uint32_t len;

    /* Apply back-pressure to the TXQ if the peer RXQ is empty. */
    if( tx_evi->selected_vfifo == VFIFO_DEFAULT && tun_fd < 0 ) {
      zf_assert(rx_evi);
      uint32_t space = (rx_evi->io.rx_doorbell - rx_evi->rxq.ptr) &
                      rx_evi->rxq.mask;
      if( space == 0 )
        break;
    }

    if( tx_evi->flags & EF_VI_TX_TIMESTAMPS )
      clock_gettime(CLOCK_MONOTONIC, &tx_evi->ts_txq[tx_ptr]);

    /* Read a descriptor and advance [tx_ptr]. */
    txq_pop(emu, tx_evi, &tx_ptr, &txbuf, &len);

    if( ZF_UNLIKELY(len > emu_conf.mtu + ethhdr_size) ) {
      ZF_ONCE(
        zf_log_emu_err(NO_STACK,
                      "Pkt of size (%d) > mtu(%d) sent by stack"
                      " - dropping this and further such pkts\n",
                      len - ethhdr_size, emu_conf.mtu));
      /* The packet gets dropped as the stack is doing something insane.  We
      * could crash here but hopefully the application layer will be
      * affected by the drop(s) and the problem will be spotted. */
    }
    else if( ZF_LIKELY(len > 0) ) {
      if( tx_evi->selected_vfifo == VFIFO_DEFAULT ) {
        if( tun_fd >= 0 ) {
          /* Write the packet to the TUN device. */
          tun_write_packet(tun_fd, txbuf, len, ethhdr_size);
        }
        else {
          /* Copy the packet into a RX buffer on the RX VI, and write an RX
          * event. */
          zf_assert(rx_evi);
          emu_deliver(emu, rx_evi, txbuf, len);
        }
      }
      else {
        /* Queue up the packet on the vFIFO. */
        zf_assert_lt(tun_fd, 0);
        vfifo_queue* vq =
          &tx_evi->vfifo[tx_evi->hw2id[tx_evi->selected_vfifo]];
        emu_queue_packet(vq, txbuf, len);
      }
    }
  }

  /* Post TX completion and TX timestamp events. */
  if( tx_evi->flags & EF_VI_TX_TIMESTAMPS ) {
    /* With timestamps enabled, TX events don't get batched.  Write out an
      * event for each descriptor. */
    while( previous_tx_ptr != tx_ptr ) {
      evq_push_tx_ts(tx_evi, previous_tx_ptr);
      previous_tx_ptr = (previous_tx_ptr + 1) & tx_evi->txq.mask;
    }
  }
  else if( previous_tx_ptr != tx_ptr ) {
    zf_assert_le((tx_ptr - previous_tx_ptr) & tx_evi->txq.mask,
                  TX_COMPLETE_BATCH_SIZE);
    evq_push_tx(tx_evi, tx_ptr);
  }

  /* Now check for any triggered alternatives. */
  for( unsigned i = 0; i < VFIFO_MAX; i++ ) {
    vfifo_queue* vq = &tx_evi->vfifo[i];
    if( vq->first != NULL && tx_evi->vfifo_state[i] != STOP )
      emu_deliver_queue(emu, rx_evi, tx_evi, i, vq,
                        (tx_evi->vfifo_state[i] == START));
  }
}

static emu_vi *get_rx_evi_poll_candidate_x3(emu_state *emu) {
  /* Any allocated rx evi will do */
  for( int rx_vi_no = 0; rx_vi_no < emu->MAX_VIS; ++rx_vi_no ) {
    emu_vi *rx_evi_candidate = &emu->vi[rx_vi_no];
    if( rx_evi_candidate->alloced == 1 &&
        rx_evi_candidate->rxq.mask != 0 )
      return rx_evi_candidate;
  }
  return NULL;
}

static void zf_emu_poll(emu_environment* env)
{
  struct emu_state* emu = &env->state;
  int tun_fd = -1;
  const uint32_t ethhdr_size = sizeof(struct ethhdr) +
                               (emu_conf.vlan == ZF_NO_VLAN ? 0 : 4);

  /* Service each VI's TXQ. */
  for( int vi_no = 0; vi_no < emu->MAX_VIS; ++vi_no ) {
    emu_vi* tx_evi = &emu->vi[vi_no];
    emu_vi* rx_evi = NULL;

    if( tx_evi->alloced != 1 )
      continue;

    if( tx_evi->tun_fd >= 0 ) {
      /* At present, we only support a single TUN device. */
      if( tun_fd >= 0 )
        zf_assert_equal(tun_fd, tx_evi->tun_fd);
      else
        tun_fd = tx_evi->tun_fd;
    }
    else {
      if( tx_evi->nic_type == NIC_TYPE_X3 ) {
        rx_evi = get_rx_evi_poll_candidate_x3(emu);
        if( rx_evi == NULL) {
          continue;
        }
      }
      else {
        rx_evi = &emu->vi[env->peer_vis[vi_no]];
        if( rx_evi->alloced != 1 || rx_evi->rxq.mask == 0)
          continue;
      }
    }

    if( tx_evi->nic_type == NIC_TYPE_X3 ) {
      zf_emu_poll_x3(tx_evi, rx_evi, tun_fd, ethhdr_size, emu, vi_no);
    }
    else {
      zf_emu_poll_ef10(tx_evi, rx_evi, tun_fd, ethhdr_size, emu, vi_no);
    }

  }

  /* Deliver a packet from the TUN device to the appropriate RXQ. */
  if( tun_fd >= 0 ) {
    /* At present, we only support TUN with a single RX vi. */
    tun_read_packet(tun_fd, emu, &emu->vi[0], ethhdr_size);
  }
}


static void emu_state_reset(emu_state *state) {
  void *superbuf_mapping = state->superbuf_mapping;
  size_t alloced_after_init = state->memreg.alloced_after_init;
  *state = {};
  state->memreg.alloced = alloced_after_init;
  state->memreg.alloced_after_init = alloced_after_init;

  state->vis_free = {};
  for(int i = state->MAX_VIS - 1; i >= 0; i--) {
    state->vis_free.push(i);
  }

  if( emu_conf.nic_type == NIC_TYPE_X3) {
    state->superbuf_mapping = superbuf_mapping;
    memset(state->superbuf_mapping, 0xFF, superbuf_mapping_size());
    /* The first metadata block of first superbuf isn't initially used because the
    metadata of a packet is stored in the buffer for the next packet. The last packet
    of the superbuf has metadata in the subsequent superbuf. */
    memset(state->superbuf_mapping, 0x00, sizeof(ci_oword_t));

    state->unused_sbids = {};
    for(int i = CI_TEST_EFCT_MAX_SUPERBUFS - 1; i >= 0; i--) {
      state->unused_sbids.push(i);
    }

    state->sbids_in_use = {};
  
    state->buf_ptr = EFCT_RX_HEADER_NEXT_FRAME_LOC_1;
    state->donated_sbufs = 0;
    state->rxq = {};
  }
}


static int emu_init(void)
{
  int shm_fd = -1, shmaddr_fd = -1;
  int mmap_flags;

  if( emu_conf.loop || emu_conf.tun ) {
    emu_client.master = 1;
    mmap_flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB;
  }
  else {
    mmap_flags = MAP_SHARED; /* TODO: share huge paged memory */
    while(1) {
      emu_client.master = 1;
      shm_fd = shm_open(emu_conf.shmname, O_RDWR | O_CREAT | O_EXCL, S_IRWXU);
      if( shm_fd >= 0 )
        break;

      shm_fd = shm_open(emu_conf.shmname, O_RDWR, S_IRWXU);
      shm_unlink(emu_conf.shmname);
      emu_client.master = 0;
      if( shm_fd >= 0 )
        break;
    }
  }

  /* If we have two processes, we must ensure the shared memory exists in the
   * same virtual address space for both. Without this, any pointers in the
   * shared memory that go to other locations also within the shared memory
   * would only be valid on one process.
   * To fix this, we arbitrarily get a valid address from the kernel on the
   * master and store it into `*shmaddr`. This is used by the non-master
   * process to map into the same address with `MAP_FIXED`. */
  void** shmaddr = NULL;
  if( shm_fd != -1 ) {
    while( shmaddr_fd < 0 ) {
      if( emu_client.master ) {
        shmaddr_fd = shm_open(emu_conf.shmaddrname, O_RDWR | O_CREAT | O_EXCL, S_IRWXU);
      } else {
        shmaddr_fd = shm_open(emu_conf.shmaddrname, O_RDWR, S_IRWXU);
      }
    }

    shmaddr = (void**)mmap(NULL, sizeof(void*), PROT_READ | PROT_WRITE,
                           MAP_SHARED, shmaddr_fd, 0);
  }

  emu_environment* env;
  if( emu_client.master ) {
    env = (emu_environment*) mmap(NULL, shm_len(), PROT_READ | PROT_WRITE,
                                  mmap_flags, shm_fd, 0);
    if( shmaddr_fd != -1 ) {
      ZF_TRY(ftruncate(shm_fd, shm_len()));
      ZF_TRY(ftruncate(shmaddr_fd, sizeof(void*)));
      if( env != MAP_FAILED )
        *shmaddr = (void*)env;
    }
  } else {
    /* Wait until `shmaddr` has been `ftruncate`d, and a value is assigned */
    struct stat shmaddr_stat;
    do {
      ZF_TRY(fstat(shmaddr_fd, &shmaddr_stat));
    } while( ! shmaddr_stat.st_size );
    while( ! *shmaddr );

    env = (emu_environment*) mmap(*shmaddr, shm_len(), PROT_READ | PROT_WRITE,
                                  mmap_flags | MAP_FIXED, shm_fd, 0);
    shm_unlink(emu_conf.shmaddrname);
  }

  if( env == MAP_FAILED )
    zf_log_emu_err(NO_STACK,
                   "Failed to allocate huge page for emu, "
                   "are huge pages available?\n");

  ZF_TEST(env != MAP_FAILED);

  emu_client.emu_mapping = env;

  if( ! emu_client.master ) {
    for( int i = 0; ! OO_ACCESS_ONCE(env->accept_client) && i < 10000000; ++i )
      usleep(1);
    ZF_TEST(env->accept_client);
    env->shm_needs_unlinked = false;
    return 0;
  }


  /* Zero out all shared emulator state. */
  memset((void *)env, 0, shm_len());

  env->cplane_mibs.dim.llap_max = env->cplane_mibs.LLAP_TABLE_SIZE;

  /* We need to unlink the shm at tear-down if and only if we're a back-to-back
   * master.  If and when a slave comes along, it will unlink the shm as soon
   * as it has opened it, and will reset this flag. */
  zf_assert(emu_client.master);
  env->shm_needs_unlinked = ! emu_conf.loop && ! emu_conf.tun;

  env->efct_edev_ops_mutex = PTHREAD_MUTEX_INITIALIZER;

  zf_log_emu_info(NO_STACK, "HW emulation: %s, device %s, type: %s\n",
                  emu_client.master ? "master" : "client",
                  emu_conf.ifname,
                  emu_conf.tun ? "tun" :
                  (emu_conf.loop ? "loop" : "back2back"));
  if( emu_conf.tun ) {
    zf_log_emu_info(NO_STACK, "tap emu settings:\n");
    zf_log_emu_info(NO_STACK, "  tapif_addr   : %s\n",
                    inet_ntoa(in_addr{emu_conf.tunif_addr}));
    zf_log_emu_info(NO_STACK, "  local_addr   : %s\n",
                    inet_ntoa(in_addr{emu_conf.local_addr}));
    zf_log_emu_info(NO_STACK, "  tapif_netmask: %s\n",
                    inet_ntoa(in_addr{emu_conf.tunif_netmask}));
  }

  env->state.superbuf_mapping = zf_hal_mmap(env->state.superbuf_mapping, superbuf_mapping_size(),
                                            PROT_READ | PROT_WRITE,
                                            MAP_ANONYMOUS | MAP_SHARED | 
                                            MAP_HUGETLB, -1, 0);
  ZF_TEST(env->state.superbuf_mapping != MAP_FAILED);

  /* Store how much we alloced after init - memreg.alloced is affected by zf_hal_mmap */
  env->state.memreg.alloced_after_init = env->state.memreg.alloced;
  emu_state_reset(&env->state);
  return 0;
}


/* Emulates the datapath for all NICs. */
static void* zf_emu_thread(void* unused)
{
  emu_environment* env = emu_environment_get();
  ZF_TEST(env);

  while( ! OO_ACCESS_ONCE(emu_client.emu_shutdown) ) {
    bool sync = OO_ACCESS_ONCE(emu_client.request_sync);
    if( sync )
      zf_emu_update_tsync(env);

    zf_emu_poll(env);

    if( sync )
      OO_ACCESS_ONCE(emu_client.request_sync) = false;
  }

  return NULL;
}


static int emu_start(void)
{
  struct emu_state* emu = emu_state_get();

  for(uintptr_t i = 0; i < sizeof(emu->memreg.dmaaddrs) / sizeof(ef_addr); ++i) {
    /* Offset from the beginning of the packet-buffer region.  N.B. ZF makes
     * alignment assumptions about these addresses, so it's important that our
     * implicit base is huge-page aligned. */
    emu->memreg.dmaaddrs[i] = i << EF_VI_NIC_PAGE_SHIFT;
  }

  for(unsigned i = 0; i < sizeof(emu->vi) / sizeof(emu->vi[0]); ++i) {
    emu_vi* evi = &emu->vi[i];
    memcpy(evi->mac, "\x00\x0f\x53\x00\x00\x00", sizeof(evi->mac));
    evi->mac[5] = i;
    evi->selected_vfifo = VFIFO_DEFAULT;
    evi->tun_fd = -1;
  }

  if( emu_conf.tun ) {
    int netlink_socket = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if( netlink_socket < 0 )
      return -errno;

    struct sockaddr_nl addr;
    memset((void *)&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = RTMGRP_LINK;
    ZF_TRY(bind(netlink_socket, (struct sockaddr*) &addr, sizeof(addr)));

    const char *clonedev = "/dev/net/tun";
    int fd = open(clonedev, O_RDWR);
    ZF_TRY(fd);
    struct ifreq ifr = {};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, emu_conf.ifname, IF_NAMESIZE);
    ZF_TRY(ioctl(fd, TUNSETIFF, (void *) &ifr));
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    emu->vi[0].tun_fd = fd;

    int tun_ifindex = if_nametoindex(emu_conf.ifname);
    ZF_TEST(tun_ifindex != 0);

    struct {
      struct nlmsghdr  hdr;
      struct ifinfomsg msg;
    } newlink_msg;

    /* Poll the netlink socket until we receive the RTM_NEWLINK notification, or
     * until there's an error. */
    int rc;
    do {
      rc = recv(netlink_socket, &newlink_msg, sizeof(newlink_msg), 0);
      if( rc >= (int) sizeof(newlink_msg) &&
          newlink_msg.hdr.nlmsg_type == RTM_NEWLINK &&
          newlink_msg.msg.ifi_index == tun_ifindex )
        break;
    } while( rc >= 0 );
    ZF_TRY(rc);

    close(netlink_socket);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr = {};
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, emu_conf.ifname, IF_NAMESIZE-1);
    ZF_TRY(ioctl(fd, SIOCGIFADDR, &ifr));
    emu_conf.tunif_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    ZF_TRY(ioctl(fd, SIOCGIFNETMASK, &ifr));
    emu_conf.tunif_netmask = ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr;
    close(fd);
    if( emu_conf.local_addr == INADDR_ANY )
      emu_conf.local_addr = emu_conf.tunif_addr ^ htonl(3);
    ZF_TEST(emu_conf.local_addr != emu_conf.tunif_addr);
    ZF_TEST((emu_conf.local_addr & emu_conf.tunif_netmask) ==
            (emu_conf.tunif_addr & emu_conf.tunif_netmask) );
  }

  if( emu_client.master )
    ZF_TRY(pthread_create(&emu_client.thread, NULL, zf_emu_thread, NULL));

  return 0;
}

int emu_vi_number(int res, bool is_tx)
{
  return emu_conf.separate_tx ? 2 * res + is_tx : res;
}

void
zf_emu_intf_add(const char* ifname, cicp_hwport_mask_t rx_hwports,
                cicp_hwport_mask_t tx_hwports, uint16_t vlan_id,
                cicp_llap_type_t hash_policy, int peer_vi,
                const ci_mac_addr_t mac)
{
  ci_hwport_id_t first_hwport = cp_hwport_mask_first(rx_hwports);
  const ci_mac_addr_t dummy_mac = {0x00, 0x0f, 0x53, 0x00, 0x00, first_hwport};
  emu_environment* env = emu_environment_get();
  cicp_rowid_t rowid = env->cplane_mibs.llap_free_rowid++;
  cicp_llap_row_t* llap = &env->cplane_mibs.llap[rowid];

  ZF_TEST(rowid < env->cplane_mibs.LLAP_TABLE_SIZE);

  llap->ifindex = rowid + 1;
  llap->encap.link_ifindex = llap->ifindex;
  llap->mtu = emu_conf.mtu;
  llap->flags = CP_LLAP_UP;
  strcpy(llap->name, ifname);
  if( mac )
    memcpy(llap->mac, mac, sizeof(ci_mac_addr_t));
  else
    memcpy(llap->mac, dummy_mac, sizeof(dummy_mac));
  if( vlan_id > 0 ) {
    llap->encap.type = CICP_LLAP_TYPE_VLAN;
    llap->encap.vlan_id = vlan_id;
  }
  else if( ! CI_IS_POW2(rx_hwports) ) {
    llap->encap.type = CICP_LLAP_TYPE_BOND | hash_policy;
    llap->encap.vlan_id = 0;
  }
  else {
    llap->encap.type = CICP_LLAP_TYPE_NONE;
    llap->encap.vlan_id = 0;
  }
  llap->rx_hwports = rx_hwports;
  llap->tx_hwports = tx_hwports;

  /* If this is not a bond, set the peer VI.  For the bonded case, the peers
   * are specified by the slaves themselves. */
  if( CI_IS_POW2(rx_hwports) )
    env->peer_vis[emu_vi_number(first_hwport, 1)] = emu_vi_number(peer_vi, 0);
  else
    ZF_TEST(peer_vi < 0);
}


/* Fake up a MIB frame and use it to look up an interface, and also bump the
 * version so that the caller can modify the row. */
static cicp_llap_row_t* cplane_intf_mod_start(const char* ifname)
{
  struct cp_mibs mib;
  emu_environment* env = emu_environment_get();

  mib.dim = &env->cplane_mibs.dim;
  mib.llap = env->cplane_mibs.llap;
  mib.version = &env->cplane_mibs.version;
  mib.llap_version = &env->cplane_mibs.llap_version;

  cicp_rowid_t rowid = cp_llap_by_ifname(&mib, ifname);
  ZF_TEST(CICP_ROWID_IS_VALID(rowid));

  /* Bump the version number so that the caller can make a modification that
   * will be noticed by ZF. */
  ++*mib.llap_version;

  return &mib.llap[rowid];
}


void
zf_emu_intf_set_tx_hwports(const char* ifname, cicp_hwport_mask_t tx_hwports)
{
  cicp_llap_row_t* llap = cplane_intf_mod_start(ifname);
  llap->tx_hwports = tx_hwports;
}


void
zf_emu_intf_set_mac(const char* ifname, ci_mac_addr_t mac)
{
  cicp_llap_row_t* llap = cplane_intf_mod_start(ifname);
  memcpy(llap->mac, mac, sizeof(ci_mac_addr_t));
}


void
zf_emu_remove_all_intfs(void)
{
  emu_environment* env = emu_environment_get();

  memset(&env->cplane_mibs, 0, sizeof(env->cplane_mibs));
  env->cplane_mibs.dim.llap_max = env->cplane_mibs.LLAP_TABLE_SIZE;
}


void
zf_emu_set_dst_mac(const ci_mac_addr_t mac)
{
  memcpy(emu_conf.dst_mac, mac, sizeof(ci_mac_addr_t));
}


void
zf_emu_sync(void)
{
  OO_ACCESS_ONCE(emu_client.request_sync) = true;
  while( OO_ACCESS_ONCE(emu_client.request_sync) )
    sched_yield();
}


void
zf_emu_set_fw_variant(int fw_variant)
{
  emu_conf.fw_variant = fw_variant;
}

extern void
zf_emu_set_vlan_override(bool enable, uint32_t dst_addr, uint16_t vlan_id)
{
  emu_conf.vlan_override_addr = enable ? dst_addr : 0;
  emu_conf.vlan_override_id = enable ? vlan_id : emu_conf.vlan;
}


static void emu_add_default_interfaces(void)
{
  if( emu_conf.loop ) {
    /* One interface, looped back to itself. */
    zf_emu_intf_add(emu_conf.ifname, 1, 1, emu_conf.vlan, 0, 0, NULL);
  }
  else if( emu_conf.tun ) {
    /* One interface, plugged into a TUN device. */
    zf_emu_intf_add(emu_conf.ifname, 1, 1, 0, 0, -1, NULL);
  }
  else {
    /* Two interfaces, connected back-to-back. */
    zf_emu_intf_add(ZF_EMU_B2B0, 1, 1, emu_conf.vlan, 0, 1, NULL);
    zf_emu_intf_add(ZF_EMU_B2B1, 2, 2, emu_conf.vlan, 0, 0, NULL);
  }
}


static int emu_ef_driver_open(ef_driver_handle* pfd)
{
  *pfd = 0;

  return 0;
}

static int emu_ef_driver_close(ef_driver_handle pfd)
{
  return 0;
}


static void* emu_alloc_huge(size_t size)
{
  ++emu_client.driver_handle_count;

  if( emu_client.master ) {
    emu_environment* env = emu_environment_get();

    /* If the test has not specified interfaces of its own, add the default
     * interfaces according to the emulator mode. */
    if( env->cplane_mibs.llap_free_rowid == 0 )
      emu_add_default_interfaces();

    if( emu_client.driver_handle_count == 1 ) {
      env->accept_client = true;
      emu_client.emu_shutdown = false;
      emu_start();
    }
  }

  return __alloc_huge(size);
}

static void emu_free_huge(void* ptr, size_t size)
{
  if( --emu_client.driver_handle_count == 0 ) {
    emu_environment* env = emu_environment_get();

    /* We unlink the shared memory file the first time that all stacks have
     * been freed.  This is earlier than is necessary, and is a bit asymmetric
     * with creation of the file, but we don't have a convenient context for
     * doing so later on. */
    if( env->shm_needs_unlinked ) {
      shm_unlink(emu_conf.shmname);
      shm_unlink(emu_conf.shmaddrname);
      env->shm_needs_unlinked = false;
    }

    if( emu_client.master ) {
      env->accept_client = false;
      emu_client.emu_shutdown = true;
      ZF_TRY(pthread_join(emu_client.thread, NULL));

      /* reset the datapath state only.  This preserves, in particular, the
       * cplane state.  It's important that we do this when stopping the
       * emulator rather than when starting it, otherwise we can race against
       * clients in other processes that can be writing into the datapath state
       * before we've started servicing it. */
      emu_state_reset(&env->state);
    }
  }

  __free_huge(ptr, size);
}

static inline emu_vi* emu_vi_from_pd(ef_pd* pd, bool is_tx)
{
  return &emu_state_get()->vi[emu_vi_number(pd->pd_resource_id, is_tx)];
}

static inline emu_vi* emu_vi_from_ef_vi(struct ef_vi* vi)
{
  /* emu_ef_vi_alloc_from_pd() stores the driver handle in [vi->vi_resource_id]
   * so we can use it to retrieve the emu_vi given only an ef_vi pointer. */
  return &emu_state_get()->vi[vi->vi_i];
}


static int emu_ef_pd_alloc(ef_pd* pd, ef_driver_handle pd_dh,
                           int ifindex, enum ef_pd_flags flags)
{
  zf_if_info info;
  ZF_TRY(zf_cplane_get_iface_info(ifindex, &info));

  /* We should not be trying to create a VI on a bond-master. */
  ZF_TEST(CI_IS_POW2(info.rx_hwports));

  memset(pd, 0, sizeof(*pd));

  pd->pd_intf_name = strdup(info.name);
  ZF_TEST(pd->pd_intf_name);

  pd->pd_cluster_dh = pd_dh;

  /* [pd_resource_id] encodes the VI number, which is itself a function of the
   * hwport as we have a single VI (or sometimes two VIs) per interface. */
  pd->pd_resource_id = cp_hwport_mask_first(info.rx_hwports);

  return 0;
}


#define MAKE_MASK32(b) ({ typeof(b) a = (b); a |= (a >> 16); a |= (a >> 8); \
                          a |= (a >> 4); a |=(a >> 2); a |= (a >> 1);})
static int emu_ef_vi_alloc_from_pd(ef_vi* vi, ef_driver_handle vi_dh,
                            struct ef_pd* pd, ef_driver_handle pd_dh,
                            int evq_capacity, int rxq_capacity, int txq_capacity,
                            ef_vi* evq_opt, ef_driver_handle evq_dh,
                            enum ef_vi_flags flags)
{
  struct emu_state *state = emu_state_get();
  int is_tx_vi = rxq_capacity == 0;

  size_t vi_i = state->vis_free.pop();
  emu_vi* evi = &state->vi[vi_i];

  if( rxq_capacity < 0 )
    rxq_capacity = 512;
  if( txq_capacity < 0 )
    txq_capacity = 512;
  if( evq_capacity < 0 )
    evq_capacity = rxq_capacity + txq_capacity;

  int evq_mask = MAKE_MASK32((evq_capacity << 3) - 1);
  evi->evq.mask = evq_mask >> 3;
  evi->rxq.mask = rxq_capacity ? MAKE_MASK32(rxq_capacity - 1) : 0;
  evi->txq.mask = txq_capacity ? MAKE_MASK32(txq_capacity - 1) : 0;
  evi->ts_evq = {0};
  evi->flags = flags;

  memset(evi->evq.descriptors, 0xFF, sizeof(evi->evq.descriptors));
  memset(evi->rxq.descriptors, 0xFF, sizeof(evi->rxq.descriptors));
  memset(evi->txq.descriptors, 0xFF, sizeof(evi->txq.descriptors));
  memset(evi->rxq.ids, 0xFF, sizeof(evi->rxq.ids));
  memset(evi->txq.ids, 0xFF, sizeof(evi->txq.ids));

  evi->nic_type = is_tx_vi ? emu_conf.tx_nic_type : emu_conf.nic_type;

  switch( evi->nic_type ) {
    case NIC_TYPE_MEDFORD2:
      evi->evq.flags |= DMAQ_STATE_FLAG_PHASE_BIT_ON;
      evi->pio.len = sizeof(evi->pio.buffer);
      ef_vi_init(vi, EF_VI_ARCH_EF10, 'C', 1, flags, 0, &evi->ep_state);
      /* just something ef_vi could write to, never read */
      vi->vi_ctpio_mmap_ptr = (char*) evi->x3io.aperture;
      break;
    case NIC_TYPE_MEDFORD:
      evi->pio.len = sizeof(evi->pio.buffer);
      ef_vi_init(vi, EF_VI_ARCH_EF10, 'B', 2, flags, 0, &evi->ep_state);
      break;
    case NIC_TYPE_X3:
      evi->evq.flags |= DMAQ_STATE_FLAG_PHASE_BIT_ON;
      ef_vi_init(vi, EF_VI_ARCH_EFCT, 'C', 0, flags, EFHW_VI_NIC_CTPIO_ONLY,
                 &evi->ep_state);
      break;
    default:
      evi->pio.len = 2048;
      ef_vi_init(vi, EF_VI_ARCH_EF10, 'A', 3, flags, 0, &evi->ep_state);
      /* FIXME disable TCP alternatives */
      break;
  }

  strcpy(evi->intf_name, pd->pd_intf_name);

  /* We abuse the resource ID fields in the VI for storing the parameters that
   * index the emulated VIs. */
  vi->vi_resource_id = vi_dh;
  vi->vi_i = vi_i;

  vi->evq_mask = evq_mask;
  vi->evq_base = (char*) evi->evq.descriptors;
  vi->vi_rxq.mask = evi->rxq.mask;
  vi->vi_rxq.descriptors = evi->rxq.descriptors;
  vi->vi_rxq.ids = evi->rxq.ids;
  vi->vi_txq.mask = evi->txq.mask;
  vi->vi_txq.descriptors = evi->txq.descriptors;
  vi->vi_txq.ids = evi->txq.ids;
  vi->io = (ef_vi_ioaddr_t) &evi->io;
  vi->vi_stats = &evi->stats;

  if( vi->internal_ops.design_parameters ) {
    int rc;
    struct efab_nic_design_parameters dp = EFAB_NIC_DP_INITIALIZER;
    dp.rx_superbuf_bytes = EFAB_NIC_DP_DEFAULT(rx_superbuf_bytes);
    dp.rx_frame_offset = EFAB_NIC_DP_DEFAULT(rx_frame_offset);
    dp.tx_aperture_bytes = EFCT_TX_APERTURE;
    dp.tx_fifo_bytes = EFAB_NIC_DP_DEFAULT(tx_fifo_bytes);
    dp.timestamp_subnano_bits = DP_PARTIAL_TSTAMP_SUB_NANO_BITS;
    dp.unsol_credit_seq_mask = EFAB_NIC_DP_DEFAULT(unsol_credit_seq_mask);
    rc = vi->internal_ops.design_parameters(vi, &dp);
    if( rc < 0 )
      return rc;
  }

  ef_vi_init_state(vi);
  if ( evi->nic_type == NIC_TYPE_X3 ) {
    memset(evi->x3io.aperture, 0xFF, sizeof(evi->x3io.aperture));
    vi->vi_ctpio_mmap_ptr = (char*) evi->x3io.aperture;
    vi->vi_txq.ct_fifo_bytes = EFCT_TX_APERTURE;

    memset(&evi->rxq.shm, 0, sizeof(evi->rxq.shm));
    vi->efct_shm = &evi->rxq.shm;

    emu_environment* env = emu_environment_get();
    pthread_mutex_lock(&env->efct_edev_ops_mutex);
    evi->rxq.drvops = xlnx_efct_drvops();
    evi->rxq.drvops.set_param = mock_set_param;
    evi->rxq.drvops.release_superbuf = mock_release_superbuf;
    evi->rxq.drvops.bind_rxq = mock_bind_rxq;
    evi->rxq.drvops.rollover_rxq = mock_rollover_rxq;
    evi->rxq.drvops.free_rxq = mock_free_rxq;

    evi->rxq.edev = xlnx_efct_device();
    evi->rxq.edev.ops = &evi->rxq.drvops;
    pthread_mutex_unlock(&env->efct_edev_ops_mutex);

    evi->rxq.rxq_params = xlnx_efct_rxq_params();
    evi->rxq.efct_client = xlnx_efct_client();
    evi->rxq.efct_client.evi = (void*)evi;

    evi->rxq.nic_efct = efhw_nic_efct();
    evi->rxq.nic_efct.edev = &evi->rxq.edev;
    evi->rxq.nic_efct.client = &evi->rxq.efct_client;
    evi->rxq.nic_efct.rxq_n = X3_RXQ_N;

    //TODO: X3/EF10 hybrid uses ef10 io
    if ( !is_tx_vi ) {
        int n_sbufs = rxq_capacity / 512;
        /* An app requesting 1 sbuf will end up with 2 as it needs at least
         * 1 hugepage (== 2sbufs) */
        evi->rxq.superbuf_n = CI_MAX(n_sbufs, 2);
        env->state.donated_sbufs += evi->rxq.superbuf_n;
        evi->rxq.superbuf_size = 1 << 20;
        evi->rxq.superbuf_total_size = evi->rxq.superbuf_size * evi->rxq.superbuf_n;
        vi->efct_rxq[0].superbuf = (char *)state->superbuf_mapping;
        vi->efct_rxq[0].refresh_func = mock_ef_vi_efct_superbuf_refresh;

        evi->rxq.nic_efct.rxq = &env->state.rxq; 
        evi->rxq.efct_rxq = efhw_efct_rxq();

        
        vi->rx_buffer_len = 2048;
        evi->rxq.rx_buffer_len = vi->rx_buffer_len;
        evi->rxq.total_buffers = (evi->rxq.superbuf_total_size / vi->rx_buffer_len);
        vi->vi_rxq.mask = evi->rxq.total_buffers - 1;
        evi->rxq.superbuf_pkts = 512;
        evi->rxq.rollover_pkts = 1031; /* arbitrary, not a multiple of superbuf_pkts */
        evi->ep_state.rxq.rxq_ptr[0].next = 1 + evi->rxq.superbuf_pkts;
        evi->rxq.ptr = EFCT_RX_HEADER_NEXT_FRAME_LOC_1;

        /* wrapping big_buf_ptr */
        /* once buf is received, invalidate old data */
        // Account for the initial prefix metadata
        evi->rxq.superbuf_offset = (char*) vi->efct_rxq[0].superbuf - (char*)env;

        memset(&evi->rxq.shm_q[0], 0x00, sizeof(evi->rxq.shm_q[0]));
        /* hugepages given by capacity * pkt_size / hugepage_size*/
        unsigned wakeup_instance = 120320202;
        __efct_nic_rxq_bind(&evi->rxq.edev,
                      &evi->rxq.efct_client,
                      &evi->rxq.rxq_params,
                      &evi->rxq.nic_efct,
                      CI_MAX(n_sbufs / 2, 1),
                      &evi->rxq.shm_q[0],
                      wakeup_instance,
                      &evi->rxq.efct_rxq);
        vi->efct_shm->active_qs = 1;
        for (unsigned int i = 0; i < 4; i++) {
          superbuf_begin(state, evi);
        }
    }
  }
  ef_vi_add_queue(vi, vi);

  if( flags & EF_VI_RX_TIMESTAMPS ) {
    if ( evi->nic_type == NIC_TYPE_X3 ) {
      ci_qword_t time_sync;
      CI_POPULATE_QWORD_2(time_sync,
                          EFCT_TIME_SYNC_CLOCK_IS_SET, 1,
                          EFCT_TIME_SYNC_CLOCK_IN_SYNC, 1);
      evi->rxq.shm_q[0].time_sync = time_sync.u64[0];
    }

    vi->rx_prefix_len = ES_DZ_RX_PREFIX_SIZE;
    if( rxq_capacity )
      ef_vi_init_rx_timestamping(vi, 0 /* rx_correction */);
    if( txq_capacity )
      ef_vi_init_tx_timestamping(vi, 0 /* tx_correction */);
  }

  vi->inited = 1;
  evi->alloced = 1;
  return 0;
}


static int emu_ef_vi_free(ef_vi* vi, ef_driver_handle vi_dh)
{
  emu_vi* evi = emu_vi_from_ef_vi(vi);
  emu_state* state = emu_state_get();
  state->donated_sbufs -= evi->rxq.superbuf_n;
  if( evi->nic_type == NIC_TYPE_X3 ) {
    emu_environment* env = emu_environment_get();
    if(evi->rxq.superbuf_n) {
      pthread_mutex_lock(&env->efct_edev_ops_mutex);
      update_efct_edev_ops(&evi->rxq.nic_efct);
      __efct_nic_rxq_free(&evi->rxq.edev,
                          &evi->rxq.efct_client,
                          &evi->rxq.efct_rxq,
                          &emu_free_rxq);
      int qid = 0;
      int budget = 0;
      /* Polling here allows the call to `__efct_nic_rxq_free` to be processed
       * as the apps will only be flagged for deletion in that call. This makes
       * sure the resources are properly freed up for subsequent use. */
      efct_poll((void*)&evi->rxq.nic_efct, qid, budget);
      pthread_mutex_unlock(&env->efct_edev_ops_mutex);
    }
  }
  vi->inited = 0;
  evi->alloced = 0;
  state->vis_free.push(vi->vi_i);
  return 0;
}


static int emu_ef_pd_free(ef_pd* pd, ef_driver_handle vi_dh)
{
  free(pd->pd_intf_name);
  return 0;
}


static int emu_ef_pio_alloc(ef_pio* pio, ef_driver_handle pio_dh, ef_pd* pd,
                 unsigned len_hint, ef_driver_handle pd_dh)
{
  if( ! emu_conf.pio )
    return -ENOSPC;
  memset(pio, 0, sizeof(*pio));
  return 0;
}


int emu_ef_pio_free(ef_pio* pio, ef_driver_handle dh)
{
  return 0;
}


static int emu_ef_pio_link_vi(ef_pio* pio, ef_driver_handle pio_dh, ef_vi* vi,
                   ef_driver_handle vi_dh)
{
  emu_vi* evi = emu_vi_from_ef_vi(vi);

  zf_assert_equal(vi->linked_pio, NULL);

  pio->pio_buffer = evi->pio.buffer;
  pio->pio_len = evi->pio.len;
  pio->pio_io = evi->io.pio;

  vi->linked_pio = pio;

  return 0;
}


static int emu_ef_pio_unlink_vi(ef_pio* pio, ef_driver_handle pio_dh, ef_vi* vi,
                     ef_driver_handle vi_dh)
{
  zf_assert_equal(pio_dh, vi_dh);

  vi->linked_pio = NULL;

  return 0;
}


static int emu_ef_memreg_alloc(ef_memreg* mr, ef_driver_handle mr_dh,
                    ef_pd* pd, ef_driver_handle pd_dh,
                    void* p_mem, size_t len_bytes)
{
  emu_state* emu = emu_state_get();

  char* ptr = ((char*)emu) + emu_memreg_start;
  ZF_TEST( ((char*)p_mem) - ptr +  len_bytes < emu_memreg_size());
  uintptr_t ofs = ((char*)p_mem) - ptr;


  memset(mr, 0, sizeof(*mr));
  mr->mr_dma_addrs = mr->mr_dma_addrs_base =
      emu->memreg.dmaaddrs + (ofs >> EF_VI_NIC_PAGE_SHIFT);
  return 0;
}


static int emu_ef_memreg_free(ef_memreg* mr, ef_driver_handle mr_dh)
{
  return 0;
}


static int emu_ef_vi_get_mac(ef_vi* vi, ef_driver_handle dh, void* mac_out)
{
  emu_vi* evi = emu_vi_from_ef_vi(vi);

  memcpy(mac_out, evi->mac, sizeof(evi->mac));
  return 0;
}


static int
emu_ef_vi_filter_add(ef_vi *vi, ef_driver_handle dh, const ef_filter_spec *fs,
                     ef_filter_cookie *filter_cookie_out)
{
  (void) vi;
  (void) dh;
  (void) fs;
  (void) filter_cookie_out;
  return 0;
}


static int
emu_ef_vi_filter_del(ef_vi *vi, ef_driver_handle dh,
                     ef_filter_cookie *filter_cookie)
{
  (void) vi;
  (void) dh;
  (void) filter_cookie;
  return 0;
}


static int
emu_oo_cp_create(int fd, struct oo_cplane_handle* handle,
                 enum cp_sync_mode mode, ci_uint32 flags)
{
  emu_environment* env = emu_environment_get();
  unsigned i;

  /* We use the same underlying tables for both mibs, as they never change
   * concurrently with ZF calls. */
  for( i = 0; i < sizeof(handle->mib) / sizeof(handle->mib[0]); ++i ) {
    handle->mib[i].dim = &env->cplane_mibs.dim;
    handle->mib[i].llap = env->cplane_mibs.llap;
    handle->mib[i].version = &env->cplane_mibs.version;
    handle->mib[i].llap_version = &env->cplane_mibs.llap_version;
  }

  return 0;
}


enum zf_path_status
emu_zf_cplane_get_path(struct zf_stack* st, struct zf_path* path, bool wait)
{
  /* MTU is 1500. */
  path->mtu = emu_conf.mtu;
  path->vlan = emu_conf.vlan;
  if( emu_conf.vlan_override_addr == path->dst ) {
    path->mtu -= 4;
    path->vlan = emu_conf.vlan_override_id;
  }
  if( emu_conf.tun ) {
    /* Any MAC address is good for emu; */
    if( CI_IP_IS_LOOPBACK(path->dst) ) {
      /* for now natively we only support local network routing
       * this does not need to be the case though.
       * Returning NOROUTE will cause handover. */
      zf_log_emu_trace(NO_STACK, "NO ROUTE %s\n", inet_ntoa( { path->dst } ));
      path->rc = ZF_PATH_NOROUTE;
      return ZF_PATH_NOROUTE;
    }
  }
  memcpy(path->mac, emu_conf.dst_mac, sizeof(ci_mac_addr_t));
  path->src = emu_conf.local_addr;
  path->rc = ZF_PATH_OK;
  return ZF_PATH_OK;
}


int emu_ef_vi_transmit_alt_free(struct ef_vi* vi, ef_driver_handle vi_dh)
{
  vi->tx_alt_id2hw = NULL;
  vi->tx_alt_hw2id = NULL;
  vi->tx_alt_num = 0;
  return 0;
}


int emu_ef_vi_transmit_alt_alloc(struct ef_vi* vi, ef_driver_handle vi_dh,
                                 int num_alts, size_t buf_space)
{
  emu_vi* evi = emu_vi_from_ef_vi(vi);
  vi->tx_alt_num = num_alts;
  vi->tx_alt_id2hw = evi->id2hw;
  vi->tx_alt_hw2id = evi->hw2id;

  for( int i = 0; i < num_alts; i++ ) {
    vi->tx_alt_id2hw[i] = i + VFIFO_HW_ID_OFFSET;
    vi->tx_alt_hw2id[i + VFIFO_HW_ID_OFFSET] = i;
  }

  return 0;
}


static int emu_transmit_alt_stop(struct ef_vi* vi, unsigned alt_id)
{
  emu_vi* evi = emu_vi_from_ef_vi(vi);
  zf_assert(alt_id <= VFIFO_MAX);
  evi->vfifo_state[alt_id] = STOP;
  return 0;
}


static int emu_transmit_alt_go(struct ef_vi* vi, unsigned alt_id)
{
  emu_vi* evi = emu_vi_from_ef_vi(vi);
  zf_assert(alt_id <= VFIFO_MAX);
  evi->vfifo_state[alt_id] = START;
  return 0;
}


static int emu_transmit_alt_discard(struct ef_vi* vi, unsigned alt_id)
{
  emu_vi* evi = emu_vi_from_ef_vi(vi);
  zf_assert(alt_id <= VFIFO_MAX);
  evi->vfifo_state[alt_id] = DRAIN;
  return 0;
}


static int emu_ef_pd_capabilities_get(ef_driver_handle handle,
                                      ef_pd*, ef_driver_handle,
                                      enum ef_vi_capability cap, 
                                      unsigned long* value)
{
  switch( cap ) {
  case EF_VI_CAP_TX_ALTERNATIVES_VFIFOS:
    if( emu_conf.fw_variant == MC_CMD_GET_CAPABILITIES_OUT_TXDP_LOW_LATENCY ) {
      *value = VFIFO_MAX;
      return 0;
    }
    else {
      *value = 0;
      return -EOPNOTSUPP;
    }

  case EF_VI_CAP_TX_ALTERNATIVES_CP_BUFFERS:
    if( emu_conf.fw_variant == MC_CMD_GET_CAPABILITIES_OUT_TXDP_LOW_LATENCY ) {
      *value = VFIFO_BUFFER_MAX;
      return 0;
    }
    else {
      *value = 0;
      return -EOPNOTSUPP;
    }

  case EF_VI_CAP_TX_ALTERNATIVES_CP_BUFFER_SIZE:
    if( emu_conf.fw_variant == MC_CMD_GET_CAPABILITIES_OUT_TXDP_LOW_LATENCY ) {
      *value = 512;
      return 0;
    }
    else {
      *value = 0;
      return -EOPNOTSUPP;
    }

  case EF_VI_CAP_RX_FW_VARIANT:
    *value = emu_conf.fw_variant;
    return 0;

  case EF_VI_CAP_TX_FW_VARIANT:
    *value = emu_conf.fw_variant;
    return 0;

  case EF_VI_CAP_CTPIO:
    if( emu_conf.tx_nic_type == NIC_TYPE_MEDFORD2 ) {
      *value = 1;
      return 0;
    }
    else {
      *value = 0;
      return -EOPNOTSUPP;
    }

  case EF_VI_CAP_RX_FILTER_TYPE_IP_VLAN:
    if( emu_conf.fw_variant == MC_CMD_GET_CAPABILITIES_OUT_RXDP ) {
      *value = 1;
      return 0;
    }
    else {
      *value = 0;
      return -EOPNOTSUPP;
    }

  default:
    zf_log_emu_err(NO_STACK,
                   "Unknown capability: %d\n", cap);
    return -ENOSYS;
  }
}


static int emu_ef_pd_transmit_alt_query_buffering(ef_vi *vi,
                                                  ef_driver_handle dh,
                                                  ef_pd *pd,
                                                  ef_driver_handle pd_dh,
                                                  int n_alts)
{
  return VFIFO_BUFFER_MAX * 512;
}

static void emu_ef_vi_transmitv_ctpio(ef_vi* vi, size_t frame_len,
                                     const struct iovec* iov, int iovcnt,
                                     unsigned threshold)
{
  /* call ef_vi_transmitv_ctpio to ensure at least that fallback copy
   * is populated as expected.
   * In case of X2 the data will make through the fallback DMA. */
  ef_vi_transmitv_ctpio(vi, frame_len, iov, iovcnt, threshold);
}

static void emu_ef_vi_transmitv_ctpio_copy(ef_vi* vi, size_t frame_len,
                                           const struct iovec* iov, int iovcnt,
                                           unsigned threshold, void* fallback)
{
  /* call ef_vi_transmitv_ctpio_copy to ensure at least that fallback copy
   * is populated as expected.
   * In case of X2 the data will make through the fallback DMA. */
  ef_vi_transmitv_ctpio_copy(vi, frame_len, iov, iovcnt, threshold, fallback);
}

static int emu_oo_fd_open(int *fd_out)
{
  *fd_out = 0;
  return 0;
}


static int emu_oo_fd_close(int)
{
  return 0;
}


static int
emu_oo_dshm_register(int, int shm_class, void* addr, uint32_t length)
{
  zf_assert_lt(shm_class, OO_DSHM_CLASS_COUNT);

  /* Allocate some metadata for the buffer. */
  auto buffer = (struct emu_oo_dshm_buffer*)
                malloc(sizeof(emu_oo_dshm_buffer));
  if( buffer == NULL )
    return -ENOMEM;

  buffer->addr = addr;
  buffer->length = length;
  buffer->buffer_id = emu_oo_dshm_state.next_buffer_id++;
  ci_dllist_push(&emu_oo_dshm_state.buffers[shm_class], &buffer->link);

  return buffer->buffer_id;
}


/* Utility function for looking up a buffer. */
static struct emu_oo_dshm_buffer*
emu_oo_dshm_lookup(int shm_class, int buffer_id)
{
  /* Find the buffer by walking the list. */
  ci_dllist* list = &emu_oo_dshm_state.buffers[shm_class];
  ci_dllink* link;

  CI_DLLIST_FOR_EACH(link, list) {
    auto this_buffer = ZF_CONTAINER(struct emu_oo_dshm_buffer, link, link);
    if( this_buffer->buffer_id == buffer_id )
      return this_buffer;
  }

  return NULL;
}


static int
emu_oo_dshm_map(int, int shm_class, int buffer_id, uint32_t len,
                void** addr_out)
{
  zf_assert_lt(shm_class, OO_DSHM_CLASS_COUNT);

  struct emu_oo_dshm_buffer* buffer = emu_oo_dshm_lookup(shm_class, buffer_id);
  if( buffer == NULL )
    return -ENOENT;

  /* This process already has a mapping of the stack, but we want to simulate
   * the driver's behaviour, which results in a new mapping.  Unfortunately,
   * we can't mremap() huge pages, so we just make a static copy. */
  *addr_out = mmap(NULL, buffer->length, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if( *addr_out == MAP_FAILED )
    return -errno;
  memcpy(*addr_out, buffer->addr, buffer->length);

  return 0;
}


static int
emu_oo_dshm_list(int, int shm_class, int* buffer_ids, uint32_t count)
{
  zf_assert_lt(shm_class, OO_DSHM_CLASS_COUNT);

  int num_returned = 0;

  ci_dllist* list = &emu_oo_dshm_state.buffers[shm_class];
  ci_dllink* link;

  /* Write each ID into the caller's array. */
  CI_DLLIST_FOR_EACH(link, list) {
    if( (size_t) num_returned >= count )
      break;

    auto this_buffer = ZF_CONTAINER(struct emu_oo_dshm_buffer, link, link);
    buffer_ids[num_returned++] = this_buffer->buffer_id;
  }

  return num_returned;
}


void* zf_hal_mmap(void *addr, size_t length, int prot,
                  int flags, int fd, off_t offset)
{
  if( !zf_hal_is_emu() )
    return mmap(addr, length, prot, flags, fd, offset);

  emu_state* emu = emu_state_get();

  uintptr_t base = (uintptr_t)((char *) emu + emu_memreg_start + emu->memreg.alloced);
  uintptr_t ptr = flags & MAP_HUGETLB ? ROUND_UP(base, huge_page_size) : base;
  length = ROUND_UP(length, huge_page_size) + (ptr - base);

  if( emu->memreg.alloced + length > emu_memreg_size() )
    return MAP_FAILED;

  emu->memreg.alloced += length;
  return (void *) ptr;
}


int zf_hal_munmap(void* addr, size_t length)
{
  if( !zf_hal_is_emu() )
    return munmap(addr, length);
  return 0;
}


int zf_hal_init(struct zf_attr* attr)
{
  const ci_mac_addr_t dummy_mac = {0x00, 0x0f, 0x53, 0x00, 0x00, 0x00};

  if( attr->emu ) {
    hal_ops = &emu_hal_ops;
    emu_conf.nic_type = attr->emu_nic;
    emu_conf.tx_nic_type = attr->tx_emu_nic;
    emu_conf.separate_tx = attr->force_separate_tx_vi;
    emu_conf.pio = attr->emu_pio;
    emu_conf.max_sbufs = attr->max_sbufs;
    strncpy(emu_conf.ifname, attr->interface, IF_NAMESIZE);
    emu_conf.ifname[IF_NAMESIZE] = '\0';
    zf_emu_set_dst_mac(dummy_mac);
    zf_emu_set_fw_variant(MC_CMD_GET_CAPABILITIES_OUT_TXDP_LOW_LATENCY);
    emu_conf.shmname[strlen(SHMNAME_PREFIX)] = '\0';
    /* Construct the name for the SHM file using the explicit name if provided,
     * or else the interface name. */
    strncat(emu_conf.shmname,
            attr->emu_shmname != NULL ? attr->emu_shmname : attr->interface,
            IF_NAMESIZE);
    emu_conf.shmname[strlen(SHMNAME_PREFIX) + IF_NAMESIZE] = '\0';

    emu_conf.shmaddrname[strlen(SHMADDRNAME_PREFIX)] = '\0';
    strncat(emu_conf.shmaddrname,
            attr->emu_shmname != NULL ? attr->emu_shmname : attr->interface,
            IF_NAMESIZE);
    emu_conf.shmaddrname[strlen(SHMADDRNAME_PREFIX) + IF_NAMESIZE] = '\0';

    emu_conf.vlan = attr->emu_vlan;
    emu_conf.mtu = attr->emu_mtu;
    if( attr->emu == ZF_EMU_LOOPBACK ){
      emu_conf.loop = 1;
    }
    if( attr->emu == ZF_EMU_TUN ){
      /* no vlan for TUN emu */
      ZF_TEST(emu_conf.vlan == ZF_NO_VLAN);
      emu_conf.tun = 1;
      if( attr->emu_tun_ip )
        emu_conf.local_addr = inet_addr(attr->emu_tun_ip);
    }

    for( int i = 0; i < OO_DSHM_CLASS_COUNT; ++i )
      ci_dllist_init(&emu_oo_dshm_state.buffers[i]);
    emu_oo_dshm_state.next_buffer_id = 0;
  }
  return 0;
}

static bool zf_emu_check_sbufleak(emu_state &state) {
  std::array<bool, CI_TEST_EFCT_MAX_SUPERBUFS> sbids_held;
  sbids_held.fill(false);
  for(auto &sbid : state.unused_sbids) {
    zf_assert(sbid < CI_TEST_EFCT_MAX_SUPERBUFS);
    if(sbids_held[sbid]) { return true; }
    sbids_held[sbid] = true;
  }

  for(auto &sbid : state.sbids_in_use) {
    zf_assert(sbid < CI_TEST_EFCT_MAX_SUPERBUFS);
    if(sbids_held[sbid]) { return true; }
    sbids_held[sbid] = true;
  }

  for(const auto &sbid_held : sbids_held) {
    if(!sbid_held) { return true; }
  }
  return false;
}


struct emu_stats& emu_stats_update() {
  emu_environment &env = *emu_environment_get();
  emu_state &state = env.state;
  emu_stats &stats = state.stats;

  size_t alloced= 0;
  for(auto i = 0; i < emu_state::MAX_VIS; i++) {
    emu_vi &evi = state.vi[i];
    if(evi.alloced == 1 && evi.rxq.mask != 0) {
      stats.efct_shm_stats.stats[alloced++] =
        reinterpret_cast<efab_efct_rxq_uk_shm_q_stats *>(&evi.rxq.shm_q[0].stats);
    }
  }
  stats.efct_shm_stats.alloced = alloced;
  stats.sbuf_leaked = zf_emu_check_sbufleak(state);
  return stats;
}

void emu_stats_display(struct emu_stats& stats) {
  for(size_t i = 0; i < CI_TEST_EFCT_MAX_SUPERBUFS; i++) {
    if(stats.sbufs[i].n_starts | stats.sbufs[i].n_ends |
       stats.sbufs[i].n_rollovers) {
      printf("sbid: %zu starts: %zu, ends: %zu, rollovers: %zu\n", i,
             stats.sbufs[i].n_starts, stats.sbufs[i].n_ends,
             stats.sbufs[i].n_rollovers);
    }
  }
  for(int i = 0; i < stats.efct_shm_stats.alloced; i++) {
    printf("vi: %d norxq_space: %u, too_many_owned %u, no_bufs: %u, "
           "skipped_bufs: %u\n", i,
            stats.efct_shm_stats.stats[i]->no_rxq_space,
            stats.efct_shm_stats.stats[i]->too_many_owned,
            stats.efct_shm_stats.stats[i]->no_bufs,
            stats.efct_shm_stats.stats[i]->skipped_bufs);
  }
  printf("no_desc_drops: %zu\n", stats.no_desc_drops);
}

int zf_hal_is_emu(void)
{
  return hal_ops != &real_hal_ops;
}


void
zf_emu_pftf_pause(ef_vi* vi)
{
  emu_vi* evi = emu_vi_from_ef_vi(vi);
  /* wait for emu to sync as we do not want to pause on
   * an old event */
  zf_emu_sync();
  OO_ACCESS_ONCE(evi->pftf_pause)++;
}


void
zf_emu_pftf_pause(zf_stack* st, int nic)
{
  zf_emu_pftf_pause(&st->nic[nic].vi);
}


void
zf_emu_pftf_resume(ef_vi* vi)
{
  emu_vi* evi = emu_vi_from_ef_vi(vi);
  OO_ACCESS_ONCE(evi->pftf_resume)++;
}



void
zf_emu_pftf_resume(zf_stack* st, int nic)
{
  zf_emu_pftf_resume(&st->nic[nic].vi);
}


struct hal_ops_s emu_hal_ops = {
  emu_ef_driver_open,
  emu_ef_driver_close,
  emu_ef_pd_alloc,
  emu_ef_vi_alloc_from_pd,
  emu_ef_vi_free,
  emu_ef_pd_free,
  emu_ef_pio_alloc,
  emu_ef_pio_free,
  emu_ef_pio_link_vi,
  emu_ef_pio_unlink_vi,
  emu_ef_memreg_alloc,
  emu_ef_memreg_free,
  emu_ef_vi_get_mac,
  emu_ef_vi_filter_add,
  emu_ef_vi_filter_del,
  emu_oo_cp_create,
  emu_zf_cplane_get_path,
  emu_oo_fd_open,
  emu_oo_fd_close,
  emu_oo_dshm_register,
  emu_oo_dshm_map,
  emu_oo_dshm_list,
  emu_ef_vi_transmit_alt_alloc,
  emu_ef_vi_transmit_alt_free,
  emu_transmit_alt_stop,
  emu_transmit_alt_go,
  emu_transmit_alt_discard,
  emu_ef_pd_capabilities_get,
  emu_ef_pd_transmit_alt_query_buffering,
  emu_ef_vi_transmitv_ctpio,
  emu_ef_vi_transmitv_ctpio_copy,
  emu_alloc_huge,
  emu_free_huge,
};


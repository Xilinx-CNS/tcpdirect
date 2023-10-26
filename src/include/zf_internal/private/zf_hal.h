/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  mj
**  \brief  Hardware abstraction layer - to allow using emulation
**    \cop  (c) SolarFlare Communications.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ZF_HAL_H__
#define __ZF_HAL_H__

#include <zf_internal/platform.h>

/* Pull this header instead of any of etherfabric files beside vi.h */
#include <etherfabric/pd.h>
#include <etherfabric/pio.h>
#include <etherfabric/memreg.h>
#include <etherfabric/vi.h>
#include <etherfabric/ef_vi.h>
#include <etherfabric/capabilities.h>

/* Control plane headers. */
#include <zf_internal/cplane.h>

/* dshm */
#include <onload/driveraccess.h>
#include <zf_internal/dshm.h>

/* alloc_huge/free_huge */
#include <zf_internal/huge.h>

#include <sys/mman.h>


struct zf_attr;
ZF_COLD extern int zf_hal_init(struct zf_attr*);

ZF_COLD extern void*
zf_hal_mmap(void* addr, size_t length, int prot, int flags,
            int fd, off_t offset);

ZF_COLD extern int
zf_hal_munmap(void* addr, size_t length);


/* private ciul APIs */
extern "C" int
ef_pd_capabilities_get(ef_driver_handle handle, ef_pd* pd,
                       ef_driver_handle pd_dh, enum ef_vi_capability cap,
                       unsigned long* value);
extern "C" int
ef_pd_transmit_alt_query_buffering(ef_vi * vi,
                                   ef_driver_handle dh, ef_pd* pd,
                                   ef_driver_handle pd_dh,
                                   int n_alts);

#ifdef ZF_DEVEL

enum {
  ZF_EMU_BACKTOBACK = 1,
  ZF_EMU_LOOPBACK   = 2,
  ZF_EMU_TUN        = 3,
};

#define ZFHAL_CONCAT(a,b) a##b
#define ZFHAL_EF_FDECL(a) typeof(ZFHAL_CONCAT(ef_,a))* a
#define ZFHAL_GEN_FDECL(func,field) typeof(func)* field
#define ZFHAL_EFOP_FDECL(a) typeof(*((ef_vi *)NULL)->ops.a)* a

struct hal_ops_s {
  ZFHAL_EF_FDECL(driver_open);
  ZFHAL_EF_FDECL(driver_close);
  ZFHAL_EF_FDECL(pd_alloc);
  ZFHAL_EF_FDECL(vi_alloc_from_pd);
  ZFHAL_EF_FDECL(vi_free);
  ZFHAL_EF_FDECL(pd_free);
  ZFHAL_EF_FDECL(pio_alloc);
  ZFHAL_EF_FDECL(pio_free);
  ZFHAL_EF_FDECL(pio_link_vi);
  ZFHAL_EF_FDECL(pio_unlink_vi);
  ZFHAL_EF_FDECL(memreg_alloc);
  ZFHAL_EF_FDECL(memreg_free);
  ZFHAL_EF_FDECL(vi_get_mac);
  ZFHAL_EF_FDECL(vi_filter_add);
  ZFHAL_EF_FDECL(vi_filter_del);
  ZFHAL_GEN_FDECL(oo_cp_create, cplane_handle);
  ZFHAL_GEN_FDECL(__zf_cplane_get_path, get_path);
  ZFHAL_GEN_FDECL(oo_fd_open, oo_fd_open_halop);
  ZFHAL_GEN_FDECL(oo_fd_close, oo_fd_close_halop);
  ZFHAL_GEN_FDECL(oo_dshm_register, shm_register);
  ZFHAL_GEN_FDECL(oo_dshm_map, shm_map);
  ZFHAL_GEN_FDECL(oo_dshm_list, shm_list);
  ZFHAL_EF_FDECL(vi_transmit_alt_alloc);
  ZFHAL_EF_FDECL(vi_transmit_alt_free);
  ZFHAL_EFOP_FDECL(transmit_alt_stop);
  ZFHAL_EFOP_FDECL(transmit_alt_go);
  ZFHAL_EFOP_FDECL(transmit_alt_discard);
  ZFHAL_EF_FDECL(pd_capabilities_get);
  ZFHAL_EF_FDECL(pd_transmit_alt_query_buffering);
  ZFHAL_EFOP_FDECL(transmitv_ctpio);
  ZFHAL_EFOP_FDECL(transmitv_ctpio_copy);
  ZFHAL_GEN_FDECL(__alloc_huge, alloc_huge);
  ZFHAL_GEN_FDECL(__free_huge, free_huge);
};

extern struct hal_ops_s* hal_ops;

#undef ZFHAL_GEN_FDECL
#undef ZFHAL_EF_FDECL
#undef ZFHAL_CONCAT

#ifndef __COMPILING_ZF_EMU__
#define ef_driver_open hal_ops->driver_open
#define ef_driver_close hal_ops->driver_close
#define ef_pd_alloc hal_ops->pd_alloc
#define ef_vi_alloc_from_pd hal_ops->vi_alloc_from_pd
#define ef_vi_free hal_ops->vi_free
#define ef_pd_free hal_ops->pd_free
#define ef_pio_alloc hal_ops->pio_alloc
#define ef_pio_free hal_ops->pio_free
#define ef_pio_link_vi hal_ops->pio_link_vi
#define ef_pio_unlink_vi hal_ops->pio_unlink_vi
#define ef_memreg_alloc hal_ops->memreg_alloc
#define ef_memreg_free hal_ops->memreg_free
#define ef_vi_get_mac hal_ops->vi_get_mac
#define ef_vi_filter_add hal_ops->vi_filter_add
#define ef_vi_filter_del hal_ops->vi_filter_del
#undef oo_cp_create
#define oo_cp_create hal_ops->cplane_handle
#define oo_fd_open hal_ops->oo_fd_open_halop
#define oo_fd_close hal_ops->oo_fd_close_halop
#define oo_dshm_register hal_ops->shm_register
#define oo_dshm_map hal_ops->shm_map
#define oo_dshm_list hal_ops->shm_list
#define ef_vi_transmit_alt_alloc hal_ops->vi_transmit_alt_alloc
#define ef_vi_transmit_alt_free hal_ops->vi_transmit_alt_free
#undef ef_vi_transmit_alt_stop
#define ef_vi_transmit_alt_stop hal_ops->transmit_alt_stop
#undef ef_vi_transmit_alt_go
#define ef_vi_transmit_alt_go hal_ops->transmit_alt_go
#undef ef_vi_transmit_alt_discard
#define ef_vi_transmit_alt_discard hal_ops->transmit_alt_discard
#define ef_pd_capabilities_get hal_ops->pd_capabilities_get
#define ef_pd_transmit_alt_query_buffering hal_ops->pd_transmit_alt_query_buffering
#undef ef_vi_transmitv_ctpio
#define ef_vi_transmitv_ctpio hal_ops->transmitv_ctpio
#undef ef_vi_transmitv_ctpio_copy
#define ef_vi_transmitv_ctpio_copy hal_ops->transmitv_ctpio_copy
#endif /* ! defined(__COMPILING_ZF_EMU__) */
#endif /* defined(ZF_DEVEL) */

#if ( defined(ZF_DEVEL) && ! defined(__COMPILING_ZF_EMU__) )
# define zf_cplane_get_path hal_ops->get_path
# define alloc_huge         hal_ops->alloc_huge
# define free_huge          hal_ops->free_huge
#else
# define zf_cplane_get_path __zf_cplane_get_path
# define alloc_huge         __alloc_huge
# define free_huge          __free_huge
#endif


#endif /* __ZF_HAL_H__ */

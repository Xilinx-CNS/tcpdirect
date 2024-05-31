/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */

/* Needed to compile onload driver superbuf code in tcpdirect test unit context.
 * Provides compatibility to allow building in user level code.
 */

#ifndef __ZF_EMU_SUPERBUF_H__
#define __ZF_EMU_SUPERBUF_H__

#define CI_HAVE_EFCT_AUX 1
#define CI_HAVE_CNS_AUX 1
#define CI_HAVE_AUX_BUS 1
#define CI_HAVE_X3_NET 1

/* prevent ci/driver/ci_efct.h and ci_aux.h from getting included */
#define CI_DRIVER_CI_EFCT_H

#include <zf_internal/private/zf_emu.h>

#include <ci/tools/sysdep.h>
#include <ci/tools/debug.h>
#include <ci/tools/log.h>

#include <linux/if_ether.h>


/* Additional kernel compat */
struct file;
struct cpumask;
struct work_struct {};
struct delayed_work {};
struct rcu_head {};
struct hlist_node {};
struct hlist_head {};
typedef uint32_t u32;
#define atomic_t ci_atomic_t
#define schedule_work(a)


struct xlnx_efct_rxq_params {

};

/* x3net compat
 * Avoids introducing dependency on x3net at the cost of needing to maintain these.
 */
struct xlnx_efct_poison_config {
	int qid;
	uint64_t value;
	size_t length;
};

union xlnx_efct_param_value {
	struct xlnx_efct_poison_config poison;
};

enum xlnx_efct_param {
	XLNX_EFCT_POISON_CONFIG,
};

struct xlnx_efct_client {
	void* evi;
};

struct xlnx_efct_drvops {
	int (*set_param)(struct xlnx_efct_client *handle, enum xlnx_efct_param p,
			 union xlnx_efct_param_value *arg);
	void (*release_superbuf)(struct xlnx_efct_client *handle, int rxq,
	                         int sbid);
	int (*bind_rxq)(struct xlnx_efct_client *handle,
			struct xlnx_efct_rxq_params *params);
	int (*rollover_rxq)(struct xlnx_efct_client *handle, int rxq);
	void (*free_rxq)(struct xlnx_efct_client *handle, int rxq,
	                 size_t n_hugepages);
};

struct xlnx_efct_device {
	struct xlnx_efct_drvops* ops;
};


/* efhw compat */
#define EFHW_ASSERT ci_assert
#define EFHW_ERR ci_log

#include <../driver/linux_resource/efct_superbuf.h>

#endif

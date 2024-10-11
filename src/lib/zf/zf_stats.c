/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#include <zf_internal/zf_stack.h>

/* ensure ef_vi/zf structures are the same size in case
 * of adding/removing elements
 */
static_assert( sizeof(ef_vi_stats_layout) == sizeof(zf_stats_layout),
               "ef_vi_stats_layout and zf_stats_layout size mismatch");

static_assert( offsetof(zf_stats_field_layout, evsfl_name) == offsetof(ef_vi_stats_field_layout, evsfl_name),
               "zf_stats_field_layout member evsfl_name does not match ef_vi_stats_field_layout");
static_assert( offsetof(zf_stats_field_layout, evsfl_offset) == offsetof(ef_vi_stats_field_layout, evsfl_offset),
               "zf_stats_field_layout member evsfl_name does not match ef_vi_stats_field_layout");
static_assert( offsetof(zf_stats_field_layout, evsfl_size) == offsetof(ef_vi_stats_field_layout, evsfl_size),
               "zf_stats_field_layout member evsfl_name does not match ef_vi_stats_field_layout");

static_assert( offsetof(zf_stats_layout, evsl_data_size) == offsetof(ef_vi_stats_layout, evsl_data_size),
               "zf_stats_field_layout member evsfl_name does not match ef_vi_stats_field_layout");
static_assert( offsetof(zf_stats_layout, evsl_fields_num) == offsetof(ef_vi_stats_layout, evsl_fields_num),
               "zf_stats_field_layout member evsfl_name does not match ef_vi_stats_field_layout");
static_assert( offsetof(zf_stats_layout, evsl_fields) == offsetof(ef_vi_stats_layout, evsl_fields),
               "zf_stats_field_layout member evsfl_name does not match ef_vi_stats_field_layout");


int
zf_stats_query_layout(struct zf_stack* stack,
                      const zf_stats_layout** const layout_out, int layout_sz)
{
  int i, rc = 0;
  int num_nics = stack->nics_n;

  if( num_nics > layout_sz )
    num_nics = layout_sz;

  for( i = 0; i < num_nics && rc == 0; i++ ) {
    ef_vi* vi = &stack->nic[i].vi;
    rc = ef_vi_stats_query_layout(vi,
        (const ef_vi_stats_layout** const) &layout_out[i]);
  }

  if( rc < 0 )
    return rc;
  return i;
}


int
zf_stats_query(struct zf_stack* stack, void* data,
               const zf_stats_layout** const layout,
               int nic_cnt, int do_reset)
{
  int i, rc = 0;
  int num_nics = stack->nics_n;
  char* pData = (char*)data;

  if( num_nics > nic_cnt )
    num_nics = nic_cnt;

  for( i = 0; i < num_nics && rc == 0; i++ ) {
    ef_vi* vi = &stack->nic[i].vi;
    rc = ef_vi_stats_query(vi, vi->dh, (void*)pData, do_reset);
    pData += layout[i]->evsl_data_size;
  }

  if( rc < 0 )
    return rc;
  return i;
}

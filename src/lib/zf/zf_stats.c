/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#include <zf_internal/zf_stack.h>

/* ensure ef_vi/zf structures are the same size in case
 * of adding/removing elements
 */
static_assert( sizeof(zf_stats_field_layout) == sizeof(zf_stats_field_layout),
               "ef_vi_stats_field_layout and zf_stats_field_layout size mismatch");
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
zf_stats_alloc_query_layout(struct zf_stack* stack,
                            zf_stats_collection** collection)
{
  int i, malloc_sz, rc = 0;
  int num_nics = stack->nics_n;
  zf_stats_collection* c;

  c = (zf_stats_collection*)malloc(sizeof(zf_stats_collection));
  if( c == NULL )
    return -ENOMEM;

  malloc_sz = num_nics * sizeof(zf_stats_layout *);
  c->layout = (zf_stats_layout**)malloc(malloc_sz);
  if( c->layout == NULL ) {
    free(c);
    return -ENOMEM;
  }
  c->num_intfs = num_nics;

  for( i = 0; i < num_nics && rc == 0; i++ ) {
    ef_vi* vi = &stack->nic[i].vi;
    rc = ef_vi_stats_query_layout(vi,
        (const ef_vi_stats_layout** const) &c->layout[i]);
  }
  

  if( rc < 0 ) {
    zf_stats_free_query_layout(c);
    return rc;
  }
  *collection = c;
  return 0;
}


void
zf_stats_free_query_layout(zf_stats_collection* collection)
{
  free(collection->layout);
  free(collection);
}


int
zf_stats_query(struct zf_stack* stack, void* data,
               zf_stats_collection* collection, int do_reset)
{
  int i, rc = 0;
  int num_intfs = stack->nics_n;
  char* pData = (char*)data;

  if( num_intfs > collection->num_intfs )
    num_intfs = collection->num_intfs;

  for( i = 0; i < num_intfs && rc == 0; i++ ) {
    ef_vi* vi = &stack->nic[i].vi;
    rc = ef_vi_stats_query(vi, vi->dh, (void*)pData, do_reset);
    pData += collection->layout[i]->evsl_data_size;
  }

  return rc;
}

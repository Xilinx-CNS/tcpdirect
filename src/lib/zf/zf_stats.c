/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#include <zf_internal/zf_stack.h>

int
zf_stats_alloc_layout_collection(struct zf_stack* stack,
                                 zf_layout_collection** collection)
{
  int i, rc = 0;
  int num_nics = stack->nics_n;
  zf_layout_collection* c;

  c = (zf_layout_collection*) malloc(sizeof(*c));
  if( c == NULL )
    return -ENOMEM;

  c->layout = (zf_stats_layout**) malloc(sizeof(*c->layout) * num_nics);
  if( c->layout == NULL ) {
    free(c);
    return -ENOMEM;
  }
  c->num_intfs = num_nics;
  c->total_data_size = 0;

  for( i = 0; i < num_nics && rc == 0; i++ ) {
    ef_vi* vi = &stack->nic[i].vi;
    rc = ef_vi_stats_query_layout(vi,
        (const ef_vi_stats_layout** const) &c->layout[i]);
    if( rc == 0 )
      c->total_data_size += c->layout[i]->evsl_data_size;
  }
  

  if( rc < 0 ) {
    zf_stats_free_layout_collection(c);
    return rc;
  }
  *collection = c;
  return 0;
}


void
zf_stats_free_layout_collection(zf_layout_collection* collection)
{
  free(collection->layout);
  free(collection);
}


int
zf_stats_query(struct zf_stack* stack, void* data,
               zf_layout_collection* collection, int do_reset)
{
  int i, rc = 0;
  int num_intfs = stack->nics_n;
  char* pData = (char*)data;

  assert(num_intfs == collection->num_intfs);

  for( i = 0; i < num_intfs && rc == 0; i++ ) {
    ef_vi* vi = &stack->nic[i].vi;
    rc = ef_vi_stats_query(vi, vi->dh, (void*)pData, do_reset);
    pData += collection->layout[i]->evsl_data_size;
  }

  return rc;
}

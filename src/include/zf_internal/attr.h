/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** ZF ATTR struct definition */

#ifndef __INT_ZF_ATTR_H__
#define __INT_ZF_ATTR_H__


#define ZF_ATTR_TYPE_int  int
#define ZF_ATTR_TYPE_str  char*
#define ZF_ATTR_TYPE_bitmask uint64_t


struct zf_attr {
  /* Attribute fields. */
# define ZF_ATTR(type, name, status, default_val, default_doc, objects, doc) \
    ZF_ATTR_TYPE_##type name;
# include <zf_internal/attr_tmpl.h>
# undef ZF_ATTR
};


#define ZF_ATTR_GET_INT_DEFAULT(attr, name, default_val)        \
  (((attr)->name >= 0) ? (attr)->name : (default_val))

#define ZF_ATTR_GET_INT_ALT(attr, name, alt_name)       \
  ZF_ATTR_GET_INT_DEFAULT(attr, name, (attr)->alt_name)


#endif  /* __ZF_INT_ATTR_H__ */

/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
#include <zf/zf.h>
#include <zf_internal/attr.h>
#include <zf_internal/utils.h>
#include <zf_internal/zf_stack.h>

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

enum zf_attr_type {
  zf_attr_type_int,
  zf_attr_type_str,
  zf_attr_type_bitmask,
};


struct zf_attr_info {
  const char*       name;
  enum zf_attr_type type;
  const char*       type_str;
  const char*       status;
  const char*       default_doc;
  const char*       objects;
  const char*       doc;
  int               offset;
  int               size;
};


static struct zf_attr_info zf_attr_info[] = {
# define ZF_ATTR(_type, _name, _status, _def_val, _def_doc, _objects, _doc) { \
  .name = #_name,                                                       \
  .type = zf_attr_type_##_type,                                         \
  .type_str = #_type,                                                   \
  .status = #_status,                                                   \
  .default_doc = NULL,                                                  \
  .objects = _objects,                                                  \
  .doc = _doc,                                                          \
  .offset = ZF_MEMBER_OFFSET(struct zf_attr, _name),                    \
  .size = ZF_MEMBER_SIZE(struct zf_attr, _name)                         \
  },
# include <zf_internal/attr_tmpl.h>
# undef ZF_ATTR
};


#define ZF_ATTR_N                                       \
  (sizeof(zf_attr_info) / sizeof(zf_attr_info[0]))


#define ZF_CFG_PROC_PATH		"/proc/sys/"
/* The real max is 30, but let's use larger value. */
#define ZF_CFG_PROC_PATH_LEN_MAX	70
/* Match procfs/sysctl line limits. */
#define ZF_CFG_PROC_LINE_LEN_MAX	1025


static int zf_attr_from_str(struct zf_attr* attr, const char* str);

static int zf_attr_set_from_sysctl(struct zf_attr* attr);


static void* get_field(struct zf_attr* attr, struct zf_attr_info* f)
{
  return (char*) attr + f->offset;
}


static char** get_field_str(struct zf_attr* attr, struct zf_attr_info* f)
{
  zf_assert_equal(f->type, zf_attr_type_str);
  return (char**) get_field(attr, f);
}


static void __zf_attr_free_fields(struct zf_attr* attr)
{
  struct zf_attr_info* f;
  for( f = zf_attr_info; f < zf_attr_info + ZF_ATTR_N; ++f )
    if( f->type == zf_attr_type_str )
      free(*(get_field_str(attr, f)));
}

static inline void __safe_set_str(char** str, const char* val)
{
  if( val == NULL )
    *str = NULL;
  else
    *str = strdup(val);
}

#define ZF_ATTR_SET_str(name, def_val) \
  __safe_set_str(&attr->name, def_val);

#define ZF_ATTR_SET_int(name, def_val) \
  attr->name = def_val;

#define ZF_ATTR_SET_bitmask(name, def_val) \
  attr->name = def_val;

static void __zf_attr_reset(struct zf_attr* attr)
{
#define ZF_ATTR(type, name, status, def_val, def_doc, objects, doc)     \
  ZF_ATTR_SET_##type(name, def_val)
# include <zf_internal/attr_tmpl.h>
# undef ZF_ATTR
}


static struct zf_attr* __zf_attr_alloc(void)
{
  struct zf_attr* attr = (struct zf_attr*)calloc(1, sizeof(struct zf_attr));
  if( attr == NULL )
    return NULL;
  __zf_attr_reset(attr);
  return attr;
}


int zf_attr_alloc(struct zf_attr** attr_out)
{
  struct zf_attr* attr = __zf_attr_alloc();
  *attr_out = attr;
  if( attr == NULL )
    return -ENOMEM;
  if( zf_attr_set_from_sysctl(attr) )
    return -ENOSYS;
  const char* default_attr_str = getenv("ZF_ATTR");
  if( default_attr_str != NULL &&
      zf_attr_from_str(attr, default_attr_str) < 0 ) {
    return -EINVAL;
  }
  return 0;
}


void zf_attr_free(struct zf_attr* attr)
{
  __zf_attr_free_fields(attr);
  free(attr);
}


void zf_attr_reset(struct zf_attr* attr)
{
  __zf_attr_free_fields(attr);
  __zf_attr_reset(attr);
}


static void zf_attr_copy(struct zf_attr* to, const struct zf_attr* from)
{
  struct zf_attr_info* f;
  for( f = zf_attr_info; f < zf_attr_info + ZF_ATTR_N; ++f )
    switch( f->type ) {
    case zf_attr_type_bitmask:
    case zf_attr_type_int: {
      memcpy(get_field(to, f), get_field((struct zf_attr*) from, f), f->size);
      break;
    }
    case zf_attr_type_str: {
      char* s = *(get_field_str((struct zf_attr*) from, f));
      char** p = get_field_str(to, f);
      free(*p);
      if( s == NULL )
        *p = NULL;
      else
        *p = strdup(s);
      break;
    }
    default:
      zf_assert(0);
    }
}


struct zf_attr* zf_attr_dup(const struct zf_attr* from)
{
  struct zf_attr* to = __zf_attr_alloc();
  if( to != NULL )
    zf_attr_copy(to, from);
  return to;
}


static struct zf_attr_info* zf_attr_info_find(const char* name)
{
  struct zf_attr_info* f;
  for( f = zf_attr_info; f < zf_attr_info + ZF_ATTR_N; ++f )
    if( ! strcasecmp(name, f->name) )
      return f;
  return NULL;
}


int zf_attr_set_int(struct zf_attr* attr, const char* name, int64_t val)
{
  struct zf_attr_info* f;
  f = zf_attr_info_find(name);
  if( f != NULL ) {
    switch( f->type ) {
    case zf_attr_type_int:
    {
      if( (int64_t)(int) val != val ) {
        zf_log_stack_err(NO_STACK, 
                         "ERROR: Attribute '%s' value overflows: %"PRId64"\n",
                         name, val);
        return -EOVERFLOW;
      }
      int* pi = (int*) get_field(attr, f);
      *pi = (int) val;
      if( strcmp("log_format", f->name) == 0 )
        zf_log_format = (int)val;
      return 0;
    }
    case zf_attr_type_str:
    {
      char** ps = (char**) get_field(attr, f);
      free(*ps);
      int rc = asprintf(ps, "%"PRId64, val);
      zf_assert_gt(rc, 0);
      return 0;
    }
    case zf_attr_type_bitmask:
    {
      uint64_t* pb = (uint64_t*) get_field(attr, f);
      *pb = (uint64_t) val;
      if( strcmp("log_level", f->name) == 0 )
        zf_log_level = (uint64_t)val;
      return 0;
    }
    default:
      zf_assert(0);
      break;
    }
  }
  zf_log_stack_err(NO_STACK, "ERROR: No such attribute '%s'\n", 
                   name);
  return -ENOENT;
}


int zf_attr_get_int(struct zf_attr* attr, const char* name, int64_t* val)
{
  struct zf_attr_info* f;
  f = zf_attr_info_find(name);
  if( f == NULL )
    return -ENOENT;
  switch( f->type ) {
  case zf_attr_type_int:
    if( strcmp("log_format", f->name) == 0 )
      *val = zf_log_format;
    else
      *val = *(int*)get_field(attr, f);
    return 0;
  case zf_attr_type_bitmask:
    if( strcmp("log_level", f->name) == 0 )
      *val = zf_log_level;
    else
      *val = *(uint64_t*)get_field(attr, f);
    return 0;
  default:
    return -EINVAL;
  }
}


int zf_attr_set_str(struct zf_attr* attr, const char* name, const char* val)
{
  struct zf_attr_info* f;
  f = zf_attr_info_find(name);
  if( f != NULL ) {
    if( f->type != zf_attr_type_str ) {
      zf_log_stack_err(NO_STACK, "ERROR: Attribute '%s' has type %d\n",
                       name, f->type);
      return -ENOMSG;
    }
    char** p = get_field_str(attr, f);
    free(*p);
    if( val != NULL ) {
      if( strcmp("log_file", f->name) == 0 ) {
        int rc = zf_log_redirect(val);
        if( rc < 0 ) {
          zf_log_stack_err(NO_STACK, "%s: Failed to redirect logging: %s\n",
                          __func__, strerror(-rc));
          /* Failure here is non-fatal. */
          *p=NULL;
          return rc;
        }
      }
      *p = strdup(val);
      if( *p == NULL )
        return -ENOMEM;
    }
    else
      *p = NULL;

    return 0;
  }
  return -ENOENT;
}


int zf_attr_get_str(struct zf_attr* attr, const char* name, char** val)
{
  struct zf_attr_info* f;
  f = zf_attr_info_find(name);
  if( f == NULL )
    return -ENOENT;
  switch( f->type ) {
  case zf_attr_type_str: {
    char** p = get_field_str(attr, f);
    if( strcmp("log_file", f->name) == 0 ) {
      *val = strdup(zf_log_file_name);
      if( *val == NULL )
        return -ENOMEM;
    }
    else if( *p != NULL ) {
      *val = strdup(*p);
      if( *val == NULL )
        return -ENOMEM;
    }
    else
      *val = NULL;
    return 0;
  }
  default:
    return -EINVAL;
  }
}


int zf_attr_set_from_str(struct zf_attr* attr, const char* name,
                         const char* val)
{
  struct zf_attr_info* f;
  if( (f = zf_attr_info_find(name)) == NULL ) {
    zf_log_stack_err(NO_STACK, "ERROR: No such attribute '%s'\n",
                     name);
    return -ENOENT;
  }
  switch( f->type ) {
  case zf_attr_type_bitmask:
  {
    uint64_t tmp;
    char* endptr;
    /* strtoull() doesn't have a reliable return value on error.  Zeroing errno
     * is the method sanctioned by the manpage. */
    errno = 0;
    tmp = strtoull(val, &endptr, 0);
    if( errno != 0 || *endptr != '\0' || *val == '\0' ) {
      zf_log_stack_err(NO_STACK, "ERROR: Expected bitmask in '%s=%s'\n",
                       name, val);
      return -EINVAL;
    }
    return zf_attr_set_int(attr, name, tmp);
  }
  case zf_attr_type_int:
  {
    char dummy;
    int64_t tmp;
    if( sscanf(val, "%"PRIi64"%c", &tmp, &dummy) != 1 ) {
      zf_log_stack_err(NO_STACK, "ERROR: Expected integer in '%s=%s'\n",
              name, val);
      return -EINVAL;
    }
    return zf_attr_set_int(attr, name, tmp);
  }
  case zf_attr_type_str:
  {
    char** pf = (char**) get_field_str(attr, f);
    free(*pf);
    if( val[0] != '\0' )
      *pf = strdup(val);
    else
      *pf = NULL;
    return 0;
  }
  default:
    zf_assert(0);
    return 0;
  }
}


int zf_attr_set_from_fmt(struct zf_attr* attr,
                         const char* name, const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  char* val;
  int rc = vasprintf(&val, fmt, va);
  va_end(va);
  if( rc < 0 )
    return -ENOMEM;
  rc = zf_attr_set_from_str(attr, name, val);
  free(val);
  return rc;
}


static int __zf_attr_from_str(struct zf_attr* attr, char* str)
{
  char *next, *val;
  int rc = 0;
  int n_defs[ZF_ATTR_N];
  memset(n_defs, 0, sizeof(n_defs));
  while( *str != '\0' ) {
    if( (next = strchr(str, ';')) != NULL ) {
      /* consume duplicate colons */
      while( *next == ';' ) {
        *next = '\0';
        ++next;
      }
    }
    if( (val = strchr(str, '=')) == NULL ) {
      zf_log_stack_err(NO_STACK, "ERROR: Missing '=' in '%s'\n", str);
      rc = -1;
    } else {
      *(val++) = '\0';
      struct zf_attr_info* f;
      if( (f = zf_attr_info_find(str)) == NULL ) {
        zf_log_stack_err(NO_STACK, "ERROR: No such attribute '%s'\n",
                         str);
        rc = -ENOENT;
      } else {
        n_defs[f - zf_attr_info]++;
        int rc2 = zf_attr_set_from_str(attr, str, val);
        if( rc2 < 0 )
          rc = rc2;
      }
    }
    if( (str = next) == NULL )
      break;
  }
  for( unsigned i = 0; i < ZF_ATTR_N; i++ ) {
    if( n_defs[i] > 1 ) {
      zf_log_stack_err(NO_STACK, 
                       "WARNING: Multiple definitions of attribute '%s'"
                       " (using the last)\n",
                       zf_attr_info[i].name);
    }
  }
  return rc;
}


static int zf_attr_from_str(struct zf_attr* attr, const char* str)
{
  char* s = strdup(str);
  int rc = __zf_attr_from_str(attr, s);
  free(s);
  return rc;
}


static int zf_sysctl_get_values(const char* path, uint32_t* ret, int n,
                                int quiet)
{
  char name[ZF_CFG_PROC_PATH_LEN_MAX + strlen(ZF_CFG_PROC_PATH)];
  char buf[ZF_CFG_PROC_LINE_LEN_MAX];
  int buflen;
  char* p = buf;
  int fd;
  int i = 0;

  strcpy(name, ZF_CFG_PROC_PATH);
  strncpy(name + strlen(ZF_CFG_PROC_PATH), path, ZF_CFG_PROC_PATH_LEN_MAX);
  fd = open(name, O_RDONLY);
  if( fd < 0 ) {
    /* This message may apear if kernel is too old or in chroot, or we're in a
     * container. */
    zf_log_stack_warn(NO_STACK, "WARNING: Failed to open %s\n", name);
    return fd;
  }
  buflen = read(fd, buf, sizeof(buf));
  close(fd);
  buf[buflen - 1] = '\0';
  for( i = 0; i < n && sscanf(p, "%u", &ret[i]) > 0; ++i ) {
    while( buf + buflen > p && p[0] != '\t' )
      p++;
    p++;
  }
  if( i < n ) {
    zf_log_stack_warn(NO_STACK, "WARNING: Failed to parse %s: %s\n",
                      name, buf);
    return -1;
  }
  return 0;
}


static int zf_attr_set_from_sysctl(struct zf_attr* attr)
{
  uint32_t opt[3];

  /* The initial values of the attributes are already set to sensible defaults
   * in case we can't access any of the sysctls. */

  if( zf_sysctl_get_values("net/ipv4/tcp_max_syn_backlog", opt, 1, 0) == 0 )
    attr->max_tcp_syn_backlog = opt[0];

  if( zf_sysctl_get_values("net/ipv4/tcp_fin_timeout", opt, 1, 0) == 0 ) {
    attr->tcp_timewait_ms = 1000 * opt[0];
    attr->tcp_finwait_ms  = 1000 * opt[0];
  }

  if( zf_sysctl_get_values("net/ipv4/tcp_syn_retries", opt, 1, 0) == 0 )
    attr->tcp_syn_retries = opt[0];

  if( zf_sysctl_get_values("net/ipv4/tcp_synack_retries", opt, 1, 0) == 0 )
    attr->tcp_synack_retries = opt[0];

  if( zf_sysctl_get_values("net/ipv4/tcp_retries2", opt, 1, 0) == 0 )
    attr->tcp_retries = opt[0];

  return 0;
}

/**********************************************************************
 * Built-in attribute documentation.
 */

static const char* zf_attr_default_str(const char* val)
{
  return val ? val : strdup("");
}


static const char* zf_attr_default_int(int val)
{
  char* s;
  int rc = asprintf(&s, "%d", val);
  zf_assert_gt(rc, 0);
  return s;
}


static const char* zf_attr_default_bitmask(uint64_t val)
{
  char* s;
  int rc = asprintf(&s, "0x%"PRIx64, val);
  zf_assert_gt(rc, 0);
  return s;
}


static void zf_attr_init_default_doc(void)
{
  if( zf_attr_info[0].default_doc != NULL )
    return;
  int i = 0;
# define ZF_ATTR(_type, _name, _status, _def_val, _def_doc, _objects, _doc) \
  zf_attr_info[i++].default_doc =                                       \
    _def_doc ? _def_doc : zf_attr_default_##_type(_def_val);
# include <zf_internal/attr_tmpl.h>
# undef ZF_ATTR
  zf_assert_equal(i, ZF_ATTR_N);
}


int zf_attr_doc(const char* attr_name,
                const char*** docs_out, int* docs_len_out)
{
  if( attr_name == NULL || ! strcmp(attr_name, "") ) {
    *docs_out = (const char**) malloc(ZF_ATTR_N * sizeof(const char*));
    if( *docs_out == NULL )
      return -ENOMEM;

    unsigned i;
    for( i = 0; i < ZF_ATTR_N; ++i )
      (*docs_out)[i] = zf_attr_info[i].name;
    *docs_len_out = ZF_ATTR_N;
    return 0;
  }

  struct zf_attr_info* f = zf_attr_info_find(attr_name);
  if( f == NULL )
    return -ENOENT;
  zf_attr_init_default_doc();
  const char* docs[] = {
    f->name,
    f->type_str,
    f->status,
    f->default_doc,
    f->objects,
    f->doc ? f->doc : ""
  };
  *docs_len_out = sizeof(docs) / sizeof(docs[0]);
  *docs_out = (const char**) malloc(sizeof(docs));
  memcpy(*docs_out, docs, sizeof(docs));
  return 0;
}

/*
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2010, 2011 Free Software
 * Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#ifndef EXT_PROXYINFO_H
#define EXT_PROXYINFO_H

#include <gnutls_extensions.h>

typedef struct
{
  opaque name[MAX_SERVER_NAME_SIZE];
  unsigned name_length;
  gnutls_server_name_type_t type;
} foobar_st;

#define MAX_SERVER_NAME_EXTENSIONS 3
#define MAX_PROXIES 6

typedef struct
{
  gnutls_cipher_algorithm_t cipher_algo;
  gnutls_kx_algorithm_t kx_algo;
  gnutls_mac_algorithm_t mac_algo;
  int ip_addr;
  int mac_addr;
}gnutls_ProxyInfo_ext;

typedef struct
{
  foobar_st server_names[MAX_SERVER_NAME_EXTENSIONS];
  /* limit server_name extensions */
  unsigned server_names_size;
  gnutls_ProxyInfo_ext proxy_info[MAX_PROXIES];
  unsigned proxy_cnt;
} ProxyInfo_ext_st;

extern extension_entry_st proxyinfo_ext;

#endif

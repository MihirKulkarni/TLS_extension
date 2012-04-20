/*
 * Copyright (C) 2008, 2010, 2011 Free Software Foundation, Inc.
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

/* This file handles all the internal functions that cope with random data.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <random.h>

void *gnutls_rnd_ctx;

int
_gnutls_rnd_init (void)
{
  if (_gnutls_rnd_ops.init != NULL)
    {
      if (_gnutls_rnd_ops.init (&gnutls_rnd_ctx) < 0)
        {
          gnutls_assert ();
          return GNUTLS_E_RANDOM_FAILED;
        }
    }

  return 0;
}

void
_gnutls_rnd_deinit (void)
{
  if (_gnutls_rnd_ops.deinit != NULL)
    {
      _gnutls_rnd_ops.deinit (gnutls_rnd_ctx);
    }

  return;
}

/**
 * gnutls_rnd:
 * @level: a security level
 * @data: place to store random bytes
 * @len: The requested size
 *
 * This function will generate random data and store it to output
 * buffer.
 *
 * Returns: Zero or a negative error code on error.
 *
 * Since: 2.12.0
 **/
int
gnutls_rnd (gnutls_rnd_level_t level, void *data, size_t len)
{
  return _gnutls_rnd(level, data, len);
}

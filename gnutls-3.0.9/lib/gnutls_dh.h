/*
 * Copyright (C) 2000-2011 Free Software Foundation, Inc.
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

#ifndef GNUTLS_DH_H
#define GNUTLS_DH_H

const bigint_t *_gnutls_dh_params_to_mpi (gnutls_dh_params_t);
bigint_t gnutls_calc_dh_secret (bigint_t * ret_x, bigint_t g, bigint_t prime,
                                unsigned int q_bits);
bigint_t gnutls_calc_dh_key (bigint_t f, bigint_t x, bigint_t prime);

gnutls_dh_params_t
_gnutls_get_dh_params (gnutls_dh_params_t dh_params,
                       gnutls_params_function * func,
                       gnutls_session_t session);

#endif

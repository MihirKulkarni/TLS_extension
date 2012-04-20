/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
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

#ifndef GNUTLS_CRYPTO_BACKEND_H
# define GNUTLS_CRYPTO_BACKEND_H

# include <gnutls/crypto.h>

# define gnutls_crypto_single_cipher_st gnutls_crypto_cipher_st
# define gnutls_crypto_single_mac_st gnutls_crypto_mac_st
# define gnutls_crypto_single_digest_st gnutls_crypto_digest_st

  typedef struct
  {
    int (*init) (gnutls_cipher_algorithm_t, void **ctx, int enc);
    int (*setkey) (void *ctx, const void *key, size_t keysize);
    int (*setiv) (void *ctx, const void *iv, size_t ivsize);
    int (*encrypt) (void *ctx, const void *plain, size_t plainsize,
                    void *encr, size_t encrsize);
    int (*decrypt) (void *ctx, const void *encr, size_t encrsize,
                    void *plain, size_t plainsize);
    int (*auth) (void *ctx, const void *data, size_t datasize);
    void (*tag) (void *ctx, void *tag, size_t tagsize);
    void (*deinit) (void *ctx);
  } gnutls_crypto_cipher_st;

  typedef struct
  {
    int (*init) (gnutls_mac_algorithm_t, void **ctx);
    int (*setkey) (void *ctx, const void *key, size_t keysize);
    void (*reset) (void *ctx);
    int (*hash) (void *ctx, const void *text, size_t textsize);
    int (*output) (void *src_ctx, void *digest, size_t digestsize);
    void (*deinit) (void *ctx);
    int (*fast)(gnutls_mac_algorithm_t, const void *key, size_t keysize, const void *text, size_t textsize, void *digest);
  } gnutls_crypto_mac_st;

  typedef struct
  {
    int (*init) (gnutls_digest_algorithm_t, void **ctx);
    void (*reset) (void *ctx);
    int (*hash) (void *ctx, const void *src, size_t srcsize);
    int (*copy) (void **dst_ctx, void *src_ctx);
    int (*output) (void *src_ctx, void *digest, size_t digestsize);
    void (*deinit) (void *ctx);
    int (*fast)(gnutls_digest_algorithm_t, const void *src, size_t srcsize, void *digest);
  } gnutls_crypto_digest_st;

  typedef struct gnutls_crypto_rnd
  {
    int (*init) (void **ctx);
    int (*rnd) (void *ctx, int level, void *data, size_t datasize);
    void (*deinit) (void *ctx);
  } gnutls_crypto_rnd_st;

  typedef void *bigint_t;

  typedef struct
  {
    bigint_t g;                 /* group generator */
    bigint_t p;                 /* prime */
    int q_bits;                 /* the number of bits of q */
  } gnutls_group_st;

/**
 * gnutls_bigint_format_t:
 * @GNUTLS_MPI_FORMAT_USG: Raw unsigned integer format.
 * @GNUTLS_MPI_FORMAT_STD: Raw signed integer format, always a leading
 *   zero when positive.
 * @GNUTLS_MPI_FORMAT_PGP: The pgp integer format.
 *
 * Enumeration of different bignum integer encoding formats.
 */
  typedef enum
  {
    /* raw unsigned integer format */
    GNUTLS_MPI_FORMAT_USG = 0,
    /* raw signed integer format - always a leading zero when positive */
    GNUTLS_MPI_FORMAT_STD = 1,
    /* the pgp integer format */
    GNUTLS_MPI_FORMAT_PGP = 2
  } gnutls_bigint_format_t;

/* Multi precision integer arithmetic */
  typedef struct gnutls_crypto_bigint
  {
    bigint_t (*bigint_new) (int nbits);
    void (*bigint_release) (bigint_t n);
    /* 0 for equality, > 0 for m1>m2, < 0 for m1<m2 */
    int (*bigint_cmp) (const bigint_t m1, const bigint_t m2);
    /* as bigint_cmp */
    int (*bigint_cmp_ui) (const bigint_t m1, unsigned long m2);
    /* ret = a % b */
      bigint_t (*bigint_mod) (const bigint_t a, const bigint_t b);
    /* a = b -> ret == a */
      bigint_t (*bigint_set) (bigint_t a, const bigint_t b);
    /* a = b -> ret == a */
      bigint_t (*bigint_set_ui) (bigint_t a, unsigned long b);
    unsigned int (*bigint_get_nbits) (const bigint_t a);
    /* w = b ^ e mod m */
      bigint_t (*bigint_powm) (bigint_t w, const bigint_t b,
                               const bigint_t e, const bigint_t m);
    /* w = a + b mod m */
      bigint_t (*bigint_addm) (bigint_t w, const bigint_t a,
                               const bigint_t b, const bigint_t m);
    /* w = a - b mod m */
      bigint_t (*bigint_subm) (bigint_t w, const bigint_t a, const bigint_t b,
                               const bigint_t m);
    /* w = a * b mod m */
      bigint_t (*bigint_mulm) (bigint_t w, const bigint_t a, const bigint_t b,
                               const bigint_t m);
    /* w = a + b */ bigint_t (*bigint_add) (bigint_t w, const bigint_t a,
                                            const bigint_t b);
    /* w = a - b */ bigint_t (*bigint_sub) (bigint_t w, const bigint_t a,
                                            const bigint_t b);
    /* w = a * b */
      bigint_t (*bigint_mul) (bigint_t w, const bigint_t a, const bigint_t b);
    /* w = a + b */
      bigint_t (*bigint_add_ui) (bigint_t w, const bigint_t a,
                                 unsigned long b);
    /* w = a - b */
      bigint_t (*bigint_sub_ui) (bigint_t w, const bigint_t a,
                                 unsigned long b);
    /* w = a * b */
      bigint_t (*bigint_mul_ui) (bigint_t w, const bigint_t a,
                                 unsigned long b);
    /* q = a / b */
      bigint_t (*bigint_div) (bigint_t q, const bigint_t a, const bigint_t b);
    /* 0 if prime */
    int (*bigint_prime_check) (const bigint_t pp);
    int (*bigint_generate_group) (gnutls_group_st * gg, unsigned int bits);

    /* reads an bigint from a buffer */
    /* stores an bigint into the buffer.  returns
     * GNUTLS_E_SHORT_MEMORY_BUFFER if buf_size is not sufficient to
     * store this integer, and updates the buf_size;
     */
      bigint_t (*bigint_scan) (const void *buf, size_t buf_size,
                               gnutls_bigint_format_t format);
    int (*bigint_print) (const bigint_t a, void *buf, size_t * buf_size,
                         gnutls_bigint_format_t format);
  } gnutls_crypto_bigint_st;

#define GNUTLS_MAX_PK_PARAMS 16

  typedef struct
  {
    bigint_t params[GNUTLS_MAX_PK_PARAMS];
    unsigned int params_nr;     /* the number of parameters */
    unsigned int flags;
  } gnutls_pk_params_st;

/**
 * gnutls_pk_flag_t:
 * @GNUTLS_PK_FLAG_NONE: No flag.
 *
 * Enumeration of public-key flag.
 */
  typedef enum
  {
    GNUTLS_PK_FLAG_NONE = 0
  } gnutls_pk_flag_t;


  void gnutls_pk_params_release (gnutls_pk_params_st * p);
  void gnutls_pk_params_init (gnutls_pk_params_st * p);


#define MAX_PUBLIC_PARAMS_SIZE 4        /* ok for RSA and DSA */

/* parameters should not be larger than this limit */
#define DSA_PUBLIC_PARAMS 4
#define RSA_PUBLIC_PARAMS 2
#define ECC_PUBLIC_PARAMS 8


#define MAX_PRIV_PARAMS_SIZE GNUTLS_MAX_PK_PARAMS       /* ok for RSA and DSA */

/* parameters should not be larger than this limit */
#define DSA_PRIVATE_PARAMS 5
#define RSA_PRIVATE_PARAMS 8
#define ECC_PRIVATE_PARAMS 9

#if MAX_PRIV_PARAMS_SIZE - RSA_PRIVATE_PARAMS < 0
#error INCREASE MAX_PRIV_PARAMS
#endif

#if MAX_PRIV_PARAMS_SIZE - ECC_PRIVATE_PARAMS < 0
#error INCREASE MAX_PRIV_PARAMS
#endif

#if MAX_PRIV_PARAMS_SIZE - DSA_PRIVATE_PARAMS < 0
#error INCREASE MAX_PRIV_PARAMS
#endif


/* params are:
 * RSA:
 *  [0] is modulus
 *  [1] is public exponent
 *  [2] is private exponent (private key only)
 *  [3] is prime1 (p) (private key only)
 *  [4] is prime2 (q) (private key only)
 *  [5] is coefficient (u == inverse of p mod q) (private key only)
 *  [6] e1 == d mod (p-1)
 *  [7] e2 == d mod (q-1)
 *
 *  note that for libgcrypt that does not use the inverse of q mod p,
 *  we need to perform conversions using fixup_params().
 *
 * DSA:
 *  [0] is p
 *  [1] is q
 *  [2] is g
 *  [3] is y (public key)
 *  [4] is x (private key only)
 *
 * ECC:
 *  [0] is prime
 *  [1] is order
 *  [2] is A
 *  [3] is B
 *  [4] is Gx
 *  [5] is Gy
 *  [6] is x
 *  [7] is y
 *  [8] is k (private key)
 */

#define ECC_PRIME 0
#define ECC_ORDER 1
#define ECC_A 2
#define ECC_B 3
#define ECC_GX 4
#define ECC_GY 5
#define ECC_X 6
#define ECC_Y 7
#define ECC_K 8

#define DSA_P 0
#define DSA_Q 1
#define DSA_G 2
#define DSA_Y 3
#define DSA_X 4

#define RSA_MODULUS 0
#define RSA_PUB 1
#define RSA_PRIV 2
#define RSA_PRIME1 3
#define RSA_PRIME2 4
#define RSA_COEF 5
#define RSA_E1 6
#define RSA_E2 7

/**
 * gnutls_direction_t:
 * @GNUTLS_IMPORT: Import direction.
 * @GNUTLS_EXPORT: Export direction.
 *
 * Enumeration of different directions.
 */
  typedef enum
  {
    GNUTLS_IMPORT = 0,
    GNUTLS_EXPORT = 1
  } gnutls_direction_t;

/* Public key algorithms */
  typedef struct gnutls_crypto_pk
  {
    /* The params structure should contain the private or public key
     * parameters, depending on the operation */
    int (*encrypt) (gnutls_pk_algorithm_t, gnutls_datum_t * ciphertext,
                    const gnutls_datum_t * plaintext,
                    const gnutls_pk_params_st * pub);
    int (*decrypt) (gnutls_pk_algorithm_t, gnutls_datum_t * plaintext,
                    const gnutls_datum_t * ciphertext,
                    const gnutls_pk_params_st * priv);

    int (*sign) (gnutls_pk_algorithm_t, gnutls_datum_t * signature,
                 const gnutls_datum_t * data,
                 const gnutls_pk_params_st * priv);
    int (*verify) (gnutls_pk_algorithm_t, const gnutls_datum_t * data,
                   const gnutls_datum_t * signature,
                   const gnutls_pk_params_st * pub);
    int (*verify_params) (gnutls_pk_algorithm_t, 
                          const gnutls_pk_params_st * pub);
    int (*generate) (gnutls_pk_algorithm_t, unsigned int nbits,
                     gnutls_pk_params_st *);
    /* this function should convert params to ones suitable
     * for the above functions
     */
    int (*pk_fixup_private_params) (gnutls_pk_algorithm_t, gnutls_direction_t,
                                    gnutls_pk_params_st *);
    int (*derive) (gnutls_pk_algorithm_t, gnutls_datum_t * out,
                   const gnutls_pk_params_st * priv,
                   const gnutls_pk_params_st * pub);


  } gnutls_crypto_pk_st;

/* priority: infinity for backend algorithms, 90 for kernel
   algorithms, lowest wins
 */
  int gnutls_crypto_single_cipher_register (gnutls_cipher_algorithm_t
                                             algorithm, int priority,
                                             const
                                             gnutls_crypto_single_cipher_st *
                                             s);
  int gnutls_crypto_single_mac_register (gnutls_mac_algorithm_t algorithm,
                                          int priority,
                                          const gnutls_crypto_single_mac_st *
                                          s);
  int gnutls_crypto_single_digest_register (gnutls_digest_algorithm_t
                                             algorithm, int priority,
                                             const
                                             gnutls_crypto_single_digest_st *
                                             s);

  int gnutls_crypto_cipher_register (int priority,
                                      const gnutls_crypto_cipher_st * s);
  int gnutls_crypto_mac_register (int priority, 
                                   const gnutls_crypto_mac_st * s);
  int gnutls_crypto_digest_register (int priority, 
                                      const gnutls_crypto_digest_st * s);

  int gnutls_crypto_rnd_register (int priority,
                                   const gnutls_crypto_rnd_st * s);
  int gnutls_crypto_pk_register (int priority,
                                  const gnutls_crypto_pk_st * s);
  int gnutls_crypto_bigint_register (int priority,
                                      const gnutls_crypto_bigint_st * s);

#endif

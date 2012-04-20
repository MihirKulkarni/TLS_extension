/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
 * Portions Copyright (C) 2001 Niels Moeller
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
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

#include <gnutls_int.h>
#include <gnutls_hash_int.h>
#include <gnutls_errors.h>
#include <nettle/sha.h>
#include <nettle/hmac.h>
#include <nettle/macros.h>
#include <aes-padlock.h>
#include <assert.h>
#include <sha-padlock.h>

#ifdef HAVE_LIBNETTLE

typedef void (*update_func) (void *, unsigned, const uint8_t *);
typedef void (*digest_func) (void *, unsigned, uint8_t *);
typedef void (*set_key_func) (void *, unsigned, const uint8_t *);

struct padlock_hash_ctx
{
  union
  {
    struct sha1_ctx sha1;
    struct sha224_ctx sha224;
    struct sha256_ctx sha256;
    struct sha384_ctx sha384;
    struct sha512_ctx sha512;
  } ctx;
  void *ctx_ptr;
  gnutls_digest_algorithm_t algo;
  size_t length;
  update_func update;
  digest_func digest;
};

static int
wrap_padlock_hash_update (void *_ctx, const void *text, size_t textsize)
{
  struct padlock_hash_ctx *ctx = _ctx;

  ctx->update (ctx->ctx_ptr, textsize, text);

  return GNUTLS_E_SUCCESS;
}

static void
wrap_padlock_hash_deinit (void *hd)
{
  gnutls_free (hd);
}

#define SHA1_COMPRESS(ctx, data) (padlock_sha1_blocks((void*)(ctx)->state, data, 1))
#define SHA256_COMPRESS(ctx, data) (padlock_sha256_blocks((void*)(ctx)->state, data, 1))
#define SHA512_COMPRESS(ctx, data) (padlock_sha512_blocks((void*)(ctx)->state, data, 1))

void
padlock_sha1_update(struct sha1_ctx *ctx,
	    unsigned length, const uint8_t *data)
{
  MD_UPDATE (ctx, length, data, SHA1_COMPRESS, MD_INCR(ctx));
}

void
padlock_sha256_update(struct sha256_ctx *ctx,
	      unsigned length, const uint8_t *data)
{
  MD_UPDATE (ctx, length, data, SHA256_COMPRESS, MD_INCR(ctx));
}

void
padlock_sha512_update(struct sha512_ctx *ctx,
	      unsigned length, const uint8_t *data)
{
  MD_UPDATE (ctx, length, data, SHA512_COMPRESS, MD_INCR(ctx));
}

static void
_nettle_write_be32(unsigned length, uint8_t *dst,
		   uint32_t *src)
{
  unsigned i;
  unsigned words;
  unsigned leftover;
  
  words = length / 4;
  leftover = length % 4;

  for (i = 0; i < words; i++, dst += 4)
    WRITE_UINT32(dst, src[i]);

  if (leftover)
    {
      uint32_t word;
      unsigned j = leftover;
      
      word = src[i];
      
      switch (leftover)
	{
	default:
	  abort();
	case 3:
	  dst[--j] = (word >> 8) & 0xff;
	  /* Fall through */
	case 2:
	  dst[--j] = (word >> 16) & 0xff;
	  /* Fall through */
	case 1:
	  dst[--j] = (word >> 24) & 0xff;
	}
    }
}

static void
padlock_sha1_digest(struct sha1_ctx *ctx,
	            unsigned length, uint8_t *digest)
{
  uint32_t high, low;

  assert(length <= SHA1_DIGEST_SIZE);

  MD_PAD(ctx, 8, SHA1_COMPRESS);

  /* There are 512 = 2^9 bits in one block */  
  high = (ctx->count_high << 9) | (ctx->count_low >> 23);
  low = (ctx->count_low << 9) | (ctx->index << 3);

  /* append the 64 bit count */
  WRITE_UINT32(ctx->block + (SHA1_DATA_SIZE - 8), high);
  WRITE_UINT32(ctx->block + (SHA1_DATA_SIZE - 4), low);
  SHA1_COMPRESS(ctx, ctx->block);

  _nettle_write_be32(length, digest, ctx->state);
}

static void
padlock_sha256_digest(struct sha256_ctx *ctx,
		    unsigned length,
		    uint8_t *digest)
{
  uint32_t high, low;

  assert(length <= SHA256_DIGEST_SIZE);

  MD_PAD(ctx, 8, SHA256_COMPRESS);

  /* There are 512 = 2^9 bits in one block */  
  high = (ctx->count_high << 9) | (ctx->count_low >> 23);
  low = (ctx->count_low << 9) | (ctx->index << 3);

  /* This is slightly inefficient, as the numbers are converted to
     big-endian format, and will be converted back by the compression
     function. It's probably not worth the effort to fix this. */
  WRITE_UINT32(ctx->block + (SHA256_DATA_SIZE - 8), high);
  WRITE_UINT32(ctx->block + (SHA256_DATA_SIZE - 4), low);
  SHA256_COMPRESS(ctx, ctx->block);

  _nettle_write_be32(length, digest, ctx->state);
}

static void
padlock_sha512_digest(struct sha512_ctx *ctx,
		    unsigned length,
		    uint8_t *digest)
{
  uint64_t high, low;

  unsigned i;
  unsigned words;
  unsigned leftover;

  assert(length <= SHA512_DIGEST_SIZE);

  MD_PAD(ctx, 16, SHA512_COMPRESS);

  /* There are 1024 = 2^10 bits in one block */  
  high = (ctx->count_high << 10) | (ctx->count_low >> 54);
  low = (ctx->count_low << 10) | (ctx->index << 3);

  /* This is slightly inefficient, as the numbers are converted to
     big-endian format, and will be converted back by the compression
     function. It's probably not worth the effort to fix this. */
  WRITE_UINT64(ctx->block + (SHA512_DATA_SIZE - 16), high);
  WRITE_UINT64(ctx->block + (SHA512_DATA_SIZE - 8), low);
  SHA512_COMPRESS(ctx, ctx->block);

  words = length / 8;
  leftover = length % 8;

  for (i = 0; i < words; i++, digest += 8)
    WRITE_UINT64(digest, ctx->state[i]);

  if (leftover)
    {
      /* Truncate to the right size */
      uint64_t word = ctx->state[i] >> (8*(8 - leftover));

      do {
	digest[--leftover] = word & 0xff;
	word >>= 8;
      } while (leftover);
    }
}


static int _ctx_init(gnutls_digest_algorithm_t algo, struct padlock_hash_ctx *ctx)
{
  switch (algo)
    {
    case GNUTLS_DIG_SHA1:
      sha1_init (&ctx->ctx.sha1);
      ctx->update = (update_func) padlock_sha1_update;
      ctx->digest = (digest_func) padlock_sha1_digest;
      ctx->ctx_ptr = &ctx->ctx.sha1;
      ctx->length = SHA1_DIGEST_SIZE;
      break;
    case GNUTLS_DIG_SHA224:
      sha224_init (&ctx->ctx.sha224);
      ctx->update = (update_func) padlock_sha256_update;
      ctx->digest = (digest_func) padlock_sha256_digest;
      ctx->ctx_ptr = &ctx->ctx.sha224;
      ctx->length = SHA224_DIGEST_SIZE;
      break;
    case GNUTLS_DIG_SHA256:
      sha256_init (&ctx->ctx.sha256);
      ctx->update = (update_func) padlock_sha256_update;
      ctx->digest = (digest_func) padlock_sha256_digest;
      ctx->ctx_ptr = &ctx->ctx.sha256;
      ctx->length = SHA256_DIGEST_SIZE;
      break;
    case GNUTLS_DIG_SHA384:
      sha384_init (&ctx->ctx.sha384);
      ctx->update = (update_func) padlock_sha512_update;
      ctx->digest = (digest_func) padlock_sha512_digest;
      ctx->ctx_ptr = &ctx->ctx.sha384;
      ctx->length = SHA384_DIGEST_SIZE;
      break;
    case GNUTLS_DIG_SHA512:
      sha512_init (&ctx->ctx.sha512);
      ctx->update = (update_func) padlock_sha512_update;
      ctx->digest = (digest_func) padlock_sha512_digest;
      ctx->ctx_ptr = &ctx->ctx.sha512;
      ctx->length = SHA512_DIGEST_SIZE;
      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }
    
    return 0;
}


static int
wrap_padlock_hash_init (gnutls_digest_algorithm_t algo, void **_ctx)
{
  struct padlock_hash_ctx *ctx;
  int ret;

  ctx = gnutls_malloc (sizeof (struct padlock_hash_ctx));
  if (ctx == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ctx->algo = algo;

  if ((ret=_ctx_init( algo, ctx)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  *_ctx = ctx;

  return 0;
}

static int
wrap_padlock_hash_copy (void **bhd, void *ahd)
{
  struct padlock_hash_ctx *ctx = ahd;
  struct padlock_hash_ctx *dst_ctx;
  int ret;

  ret = wrap_padlock_hash_init (ctx->algo, bhd);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  dst_ctx = *bhd;

  memcpy (&dst_ctx->ctx, &ctx->ctx, sizeof (ctx->ctx));

  return 0;
}


static int
wrap_padlock_hash_output (void *src_ctx, void *digest, size_t digestsize)
{
  struct padlock_hash_ctx *ctx;
  ctx = src_ctx;

  if (digestsize < ctx->length)
    return gnutls_assert_val(GNUTLS_E_SHORT_MEMORY_BUFFER);

  ctx->digest (ctx->ctx_ptr, digestsize, digest);

  return 0;
}

static void
wrap_padlock_hash_reset (void *src_ctx)
{
  struct padlock_hash_ctx *ctx;
  ctx = src_ctx;

  _ctx_init(ctx->algo, ctx->ctx_ptr);
}

int wrap_padlock_hash_fast(gnutls_digest_algorithm_t algo, 
  const void* text, size_t text_size, 
  void* digest)
{
  if (algo == GNUTLS_DIG_SHA1)
    {
      uint32_t iv[5] = 
        {
          0x67452301UL,
          0xEFCDAB89UL,
          0x98BADCFEUL,
          0x10325476UL,
          0xC3D2E1F0UL,
        };
      padlock_sha1_oneshot (iv, text, text_size);
      _nettle_write_be32(20, digest, iv);
    }
  else if (algo == GNUTLS_DIG_SHA256)
    {
      uint32_t iv[8] =
        {
          0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL, 
          0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL, 
        };
      padlock_sha256_oneshot (iv, text, text_size);
      _nettle_write_be32(32, digest, iv);
    }
  else 
    {
      struct padlock_hash_ctx ctx;
      int ret;
    
      ret = _ctx_init(algo, &ctx);
      if (ret < 0)
        return gnutls_assert_val(ret);
      ctx.algo = algo;

      wrap_padlock_hash_update(&ctx, text, text_size);

      wrap_padlock_hash_output(&ctx, digest, ctx.length);
    }
  
  return 0;
}

const struct nettle_hash padlock_sha1 = _NETTLE_HASH(sha1, SHA1);
const struct nettle_hash padlock_sha224 = _NETTLE_HASH(sha224, SHA224);
const struct nettle_hash padlock_sha256 = _NETTLE_HASH(sha256, SHA256);
const struct nettle_hash padlock_sha384 = _NETTLE_HASH(sha384, SHA384);
const struct nettle_hash padlock_sha512 = _NETTLE_HASH(sha512, SHA512);

const gnutls_crypto_digest_st sha_padlock_struct = {
  .init = NULL,
  .hash = NULL,
  .output = NULL,
  .deinit = NULL,
  .fast = wrap_padlock_hash_fast
};

const gnutls_crypto_digest_st sha_padlock_nano_struct = {
  .init = wrap_padlock_hash_init,
  .hash = wrap_padlock_hash_update,
  .reset = wrap_padlock_hash_reset,
  .copy = wrap_padlock_hash_copy,
  .output = wrap_padlock_hash_output,
  .deinit = wrap_padlock_hash_deinit,
  .fast = wrap_padlock_hash_fast,
};

#endif /* HAVE_LIBNETTLE */

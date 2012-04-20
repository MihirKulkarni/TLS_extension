#include <gmp.h>
#include <nettle/nettle-types.h>
#include <nettle/dsa.h>
#include <nettle/bignum.h>
#include <gnutls_int.h>

/* assume y^2 = x^3 - 3x + b
 * instead of the generic y^2 = x^3 + ax + b
 *
 * (XXX: the generic case has been tested only
 *  with the SECG curves.)
 */
#define ECC_SECP_CURVES_ONLY

#define PK_PRIVATE 1
#define PK_PUBLIC 2

/* ---- ECC Routines ---- */
/* size of our temp buffers for exported keys */
#define ECC_BUF_SIZE 512

/* max private key size */
#define ECC_MAXSIZE  66

/** Structure defines a NIST GF(p) curve */
typedef struct {
   /** The size of the curve in octets */
   int size;

   /** name of curve */
   const char *name; 

   /** The prime that defines the field the curve is in (encoded in hex) */
   const char *prime;

   /** The fields A param (hex) */
   const char *A;

   /** The fields B param (hex) */
   const char *B;

   /** The order of the curve (hex) */
   const char *order;
  
   /** The x co-ordinate of the base point on the curve (hex) */
   const char *Gx;
 
   /** The y co-ordinate of the base point on the curve (hex) */
   const char *Gy;
} ecc_set_type;

/** A point on a ECC curve, stored in Jacbobian format such that (x,y,z) => (x/z^2, y/z^3, 1) when interpretted as affine */
typedef struct {
    /** The x co-ordinate */
    mpz_t x;

    /** The y co-ordinate */
    mpz_t y;

    /** The z co-ordinate */
    mpz_t z;
} ecc_point;

/** An ECC key */
typedef struct {
    /** Type of key, PK_PRIVATE or PK_PUBLIC */
    int type;

    mpz_t prime;
    mpz_t order;
    mpz_t A;
    mpz_t B;
    mpz_t Gx;
    mpz_t Gy;

    /** The public key */
    ecc_point pubkey;

    /** The private key */
    mpz_t k;
} ecc_key;

void ecc_sizes(int *low, int *high);
int  ecc_get_size(ecc_key *key);

int ecc_make_key(void *random_ctx, nettle_random_func random, ecc_key *key, const ecc_set_type *dp);
int ecc_make_key_ex(void *random_ctx, nettle_random_func random, ecc_key *key, mpz_t prime, mpz_t order, mpz_t A, mpz_t B, mpz_t Gx, mpz_t Gy, int timing_res);
void ecc_free(ecc_key *key);

int  ecc_shared_secret(ecc_key *private_key, ecc_key *public_key, 
                       unsigned char *out, unsigned long *outlen);

int ecc_sign_hash(const unsigned char *in,  unsigned long inlen, 
                        struct dsa_signature *signature,
                        void *random_ctx, nettle_random_func random, ecc_key *key);

int  ecc_verify_hash(struct dsa_signature * signature,
                     const unsigned char *hash, unsigned long hashlen, 
                     int *stat, ecc_key *key);

/* low level functions */
ecc_point *ecc_new_point(void);
void       ecc_del_point(ecc_point *p);

/* point ops (mp == montgomery digit) */
/* R = 2P */
int ecc_projective_dbl_point(ecc_point *P, ecc_point *R, mpz_t a,  mpz_t modulus);

/* R = P + Q */
int ecc_projective_add_point(ecc_point *P, ecc_point *Q, ecc_point *R, mpz_t A, mpz_t modulus);

/* R = kG */
int ecc_mulmod(mpz_t k, ecc_point *G, ecc_point *R, mpz_t a, mpz_t modulus, int map);
int ecc_mulmod_timing(mpz_t k, ecc_point *G, ecc_point *R, mpz_t a, mpz_t modulus, int map);

/* map P to affine from projective */
int ecc_map(ecc_point *P, mpz_t modulus);

/* check whether a point lies on the curve */
int ecc_projective_check_point (ecc_point * P, mpz_t b, mpz_t modulus);

/* helper functions */
int mp_init_multi(mpz_t *a, ...);
void mp_clear_multi(mpz_t *a, ...);


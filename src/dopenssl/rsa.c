/*
 * Copyright (c) 2013, infinit.io
 *
 * This software is provided "as is" without warranty of any kind,
 * either expressed or implied, including but not limited to the
 * implied warranties of fitness for a particular purpose.
 *
 * See the LICENSE file for more information on the terms and
 * conditions.
 */

#include <dopenssl/rsa.h>
#include <dopenssl/rand.h>
#include <dopenssl/bn.h>

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <assert.h>

/*
 * ---------- Additional Functionalities --------------------------------------
 *
 * Based on the following OpenSSL files:
 *
 *   crypto/rsa/rsa_gen.c
 */

RSA *dRSA_deduce_publickey(BIGNUM *N,
                           const unsigned char *seed, size_t seed_length)
{
  int bits,bitse,ok= -1;

  /* PATCHED[allocate an RSA key] */
  RSA *rsa = RSA_new();

  bits=BN_num_bits(N);
  bitse=(bits/2)+1;

  /* We need the RSA components non-NULL. Remaining are left unknown. */
  if (RSA_set0_key(rsa, BN_new(), BN_new(), NULL) != 1)
    goto err;

  /* PATCHED[switch to our random generator in order to ensure
             determinism. note that the dRAND module must have been
             initialized] */
  dRAND_start();
  {
    assert(RAND_get_rand_method() == &dRAND_method);

    dRAND_reset();
    RAND_seed(seed, seed_length);

    /* generate e */
    /* PATCHED[here we use our prime generator which uses our deterministic
               random generator] */
    if(!dBN_generate_prime_ex(RSA_get0_e(rsa), bitse, 0, NULL, NULL, NULL))
      goto err;
  }
  dRAND_stop();

  /* assign n */
  BN_copy(RSA_get0_n(rsa), N);

  ok=1;
  err:
  if (ok == -1)
  {
    /* PATCHED[release the RSA structure and reinitialize the
       pointer to NULL] */
    if (rsa != NULL) RSA_free(rsa);
    rsa = NULL;

    RSAerr(RSA_F_RSA_BUILTIN_KEYGEN,ERR_LIB_BN);
  }

  return rsa;
}

RSA *dRSA_deduce_privatekey(int bits,
                            const unsigned char *seed, size_t seed_length)
{
  BIGNUM *r0=NULL,*r1=NULL,*r2=NULL,*r3=NULL;
  BIGNUM *local_r0=NULL,*local_d=NULL, *local_p=NULL;
  BIGNUM *pr0,*d,*p;
  int bitse,bitsp,bitsq,ok= -1;
  BN_CTX *ctx=NULL;

  /* PATCHED[allocate an RSA key] */
  RSA *rsa = RSA_new();

  local_r0=BN_new();
  if (local_r0 == NULL) goto err;
  local_d=BN_new();
  if (local_d == NULL) goto err;
  local_p=BN_new();
  if (local_p == NULL) goto err;
  ctx=BN_CTX_new();
  if (ctx == NULL) goto err;
  BN_CTX_start(ctx);
  r0 = BN_CTX_get(ctx);
  r1 = BN_CTX_get(ctx);
  r2 = BN_CTX_get(ctx);
  r3 = BN_CTX_get(ctx);
  if (r3 == NULL) goto err;

  bitse=(bits/2)+1;
  bitsp=(bits+1)/2;
  bitsq=bits-bitsp;

  /* We need the RSA components non-NULL */
  if (RSA_set0_key(rsa, BN_new(), BN_new(), BN_new()) != 1)
    goto err;
  if (RSA_set0_factors(rsa, BN_new(), BN_new()) != 1)
    goto err;
  if (RSA_set0_crt_params(rsa, BN_new(), BN_new(), BN_new() != 1))
    goto err;

  /* PATCHED[switch to our random generator in order to ensure
             determinism. note that the dRAND module must have been
             initialized] */
  dRAND_start();
  {
    assert(RAND_get_rand_method() == &dRAND_method);

    dRAND_reset();
    RAND_seed(seed, seed_length);

    /* generate e */
    /* PATCHED[use our prime generator which uses our deterministic
               random generator] */
    if(!dBN_generate_prime_ex(RSA_get0_e(rsa), bitse, 0, NULL, NULL, NULL))
      goto err;

    /* generate p and q */
    for (;;)
    {
      if(!dBN_generate_prime_ex(RSA_get0_p(rsa), bitsp, 0, NULL, NULL, NULL))
        goto err;
      if (!BN_sub(r2,RSA_get0_p(rsa),BN_value_one())) goto err;
      if (!BN_gcd(r1,r2,RSA_get0_e(rsa),ctx)) goto err;
      if (BN_is_one(r1)) break;
    }
    for (;;)
    {
      /* When generating ridiculously small keys, we can get stuck
       * continually regenerating the same prime values. Check for
       * this and bail if it happens 3 times. */
      unsigned int degenerate = 0;
      do
      {
        if(!dBN_generate_prime_ex(RSA_get0_q(rsa), bitsq, 0, NULL, NULL, NULL))
          goto err;
      } while((BN_cmp(RSA_get0_p(rsa), RSA_get0_q(rsa)) == 0) && (++degenerate < 3));
      if(degenerate == 3)
      {
        ok = 0; /* we set our own err */
        RSAerr(RSA_F_RSA_BUILTIN_KEYGEN,RSA_R_KEY_SIZE_TOO_SMALL);
        goto err;
      }
      if (!BN_sub(r2,RSA_get0_q(rsa),BN_value_one())) goto err;
      if (!BN_gcd(r1,r2,RSA_get0_e(rsa),ctx)) goto err;
      if (BN_is_one(r1))
        break;
    }
  }
  dRAND_stop();

  if (BN_cmp(RSA_get0_p(rsa),RSA_get0_q(rsa)) < 0)
  {
    BN_swap(RSA_get0_p(rsa),RSA_get0_q(rsa));
  }

  /* calculate n */
  if (!BN_mul(RSA_get0_n(rsa),RSA_get0_p(rsa),RSA_get0_q(rsa),ctx)) goto err;

  /* calculate d */
  if (!BN_sub(r1,RSA_get0_p(rsa),BN_value_one())) goto err;        /* p-1 */
  if (!BN_sub(r2,RSA_get0_q(rsa),BN_value_one())) goto err;        /* q-1 */
  if (!BN_mul(r0,r1,r2,ctx)) goto err;    /* (p-1)(q-1) */
  if (!(RSA_test_flags(rsa, RSA_FLAG_NO_CONSTTIME)))
  {
    pr0 = local_r0;
    BN_with_flags(pr0, r0, BN_FLG_CONSTTIME);
  }
  else
    pr0 = r0;
  if (!BN_mod_inverse(RSA_get0_d(rsa),RSA_get0_e(rsa),pr0,ctx)) goto err;   /* d */

  /* set up d for correct BN_FLG_CONSTTIME flag */
  if (!(RSA_test_flags(rsa, RSA_FLAG_NO_CONSTTIME)))
  {
    d = local_d;
    BN_with_flags(d, RSA_get0_d(rsa), BN_FLG_CONSTTIME);
  }
  else
    d = RSA_get0_d(rsa);

  /* calculate d mod (p-1) */
  if (!BN_mod(RSA_get0_dmp1(rsa),d,r1,ctx)) goto err;

  /* calculate d mod (q-1) */
  if (!BN_mod(RSA_get0_dmq1(rsa),d,r2,ctx)) goto err;

  /* calculate inverse of q mod p */
  if (!(RSA_test_flags(rsa, RSA_FLAG_NO_CONSTTIME)))
  {
    p = local_p;
    BN_with_flags(p, RSA_get0_p(rsa), BN_FLG_CONSTTIME);
  }
  else
    p = RSA_get0_p(rsa);
  if (!BN_mod_inverse(RSA_get0_iqmp(rsa),RSA_get0_q(rsa),p,ctx)) goto err;

  ok=1;
  err:
  if (ok == -1)
  {
    /* PATCHED[release the RSA structure and reinitialize the
       pointer to NULL] */
    if (rsa != NULL) RSA_free(rsa);
    rsa = NULL;

    RSAerr(RSA_F_RSA_BUILTIN_KEYGEN,ERR_LIB_BN);
  }
  if (ctx != NULL)
  {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }
  if (local_p != NULL)
  {
    BN_clear_free(local_p);
  }
  if (local_d != NULL)
  {
    BN_clear_free(local_d);
  }
  if (local_r0 != NULL)
  {
    BN_clear_free(local_r0);
  }

  return rsa;
}

int dRSA_cmp_publickey(RSA *a, RSA *b)
{
  int x;

  assert(RSA_get0_n(a) != NULL);
  assert(RSA_get0_e(a) != NULL);
  assert(RSA_get0_n(b) != NULL);
  assert(RSA_get0_e(b) != NULL);

  if ((x = BN_cmp(RSA_get0_n(a), RSA_get0_n(b))) != 0)
    return x;
  if ((x = BN_cmp(RSA_get0_e(a), RSA_get0_e(b))) != 0)
    return x;

  return 0;
}

int dRSA_cmp_privatekey(RSA *a, RSA *b)
{
  int x;

  assert(RSA_get0_n(a) != NULL);
  assert(RSA_get0_e(a) != NULL);
  assert(RSA_get0_d(a) != NULL);
  assert(RSA_get0_p(a) != NULL);
  assert(RSA_get0_q(a) != NULL);
  assert(RSA_get0_dmp1(a) != NULL);
  assert(RSA_get0_dmq1(a) != NULL);
  assert(RSA_get0_iqmp(a) != NULL);
  assert(RSA_get0_n(b) != NULL);
  assert(RSA_get0_e(b) != NULL);
  assert(RSA_get0_d(b) != NULL);
  assert(RSA_get0_p(b) != NULL);
  assert(RSA_get0_q(b) != NULL);
  assert(RSA_get0_dmp1(b) != NULL);
  assert(RSA_get0_dmq1(b) != NULL);
  assert(RSA_get0_iqmp(b) != NULL);

  if ((x = BN_cmp(RSA_get0_n(a), RSA_get0_n(b))) != 0)
    return x;
  if ((x = BN_cmp(RSA_get0_e(a), RSA_get0_e(b))) != 0)
    return x;
  if ((x = BN_cmp(RSA_get0_d(a), RSA_get0_d(b))) != 0)
    return x;
  if ((x = BN_cmp(RSA_get0_p(a), RSA_get0_p(b))) != 0)
    return x;
  if ((x = BN_cmp(RSA_get0_q(a), RSA_get0_q(b))) != 0)
    return x;
  if ((x = BN_cmp(RSA_get0_dmp1(a), RSA_get0_dmp1(b))) != 0)
    return x;
  if ((x = BN_cmp(RSA_get0_dmq1(a), RSA_get0_dmq1(b))) != 0)
    return x;
  if ((x = BN_cmp(RSA_get0_iqmp(a), RSA_get0_iqmp(b))) != 0)
    return x;

  return 0;
}

int dRSA_print(RSA *rsa)
{
  char *n = NULL;
  char *e = NULL;
  char *d = NULL;
  char *p = NULL;
  char *q = NULL;
  char *dmp1 = NULL;
  char *dmq1 = NULL;
  char *iqmp = NULL;

  assert(RSA_get0_n(rsa) != NULL);
  assert(RSA_get0_e(rsa) != NULL);

  if ((n = BN_bn2hex(RSA_get0_n(rsa))) == NULL)
    return 0;
  if ((e = BN_bn2hex(RSA_get0_e(rsa))) == NULL)
    return 0;
  if (RSA_get0_d(rsa) != NULL)
    if ((d = BN_bn2hex(RSA_get0_d(rsa))) == NULL)
      return 0;
  if (RSA_get0_p(rsa) != NULL)
    if ((p = BN_bn2hex(RSA_get0_p(rsa))) == NULL)
      return 0;
  if (RSA_get0_q(rsa) != NULL)
    if ((q = BN_bn2hex(RSA_get0_q(rsa))) == NULL)
      return 0;
  if (RSA_get0_dmp1(rsa) != NULL)
    if ((dmp1 = BN_bn2hex(RSA_get0_dmp1(rsa))) == NULL)
      return 0;
  if (RSA_get0_dmq1(rsa) != NULL)
    if ((dmq1 = BN_bn2hex(RSA_get0_dmq1(rsa))) == NULL)
      return 0;
  if (RSA_get0_iqmp(rsa) != NULL)
    if ((iqmp = BN_bn2hex(RSA_get0_iqmp(rsa))) == NULL)
      return 0;

  printf("n=%s e=%s d=%s p=%s q=%s dmp1=%s dmq1=%s iqmp=%s\n",
         n, e, d, p, q, dmp1, dmq1, iqmp);

  OPENSSL_free(iqmp);
  OPENSSL_free(dmq1);
  OPENSSL_free(dmp1);
  OPENSSL_free(q);
  OPENSSL_free(p);
  OPENSSL_free(d);
  OPENSSL_free(n);
  OPENSSL_free(e);

  return 1;
}

#include "signcrypt.h"
#include <sodium.h>
#include <string.h>

typedef struct sign_state {
    crypto_generichash_state h;
    unsigned char            nonce[crypto_core_ristretto255_SCALARBYTES];
    unsigned char            r[crypto_core_ristretto255_BYTES];
    unsigned char            challenge[crypto_core_ristretto255_SCALARBYTES];
} sign_state;

static int sc25519_is_canonical(const unsigned char s[crypto_core_ristretto255_SCALARBYTES])
{
    static const unsigned char L[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                                         0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };
    unsigned char              c = 0, n = 1;
    unsigned int               i = 32;

    do {
        i--;
        c |= ((s[i] - L[i]) >> 8) & n;
        n &= ((s[i] ^ L[i]) - 1) >> 8;
    } while (i != 0);

    return (c != 0);
}

static void lp_update(crypto_generichash_state *h, const unsigned char *x, size_t x_len)
{
    unsigned char x_len_u8 = (unsigned char) x_len;

    crypto_generichash_update(h, &x_len_u8, 1);
    crypto_generichash_update(h, x, x_len);
}

int sign_before(
    unsigned char st_[STATEBYTES],
    unsigned char shared_key[SHAREDBYTES], 
    const unsigned char *info, size_t info_len,
    const unsigned char sender_sk[crypto_core_ristretto255_SCALARBYTES],
    const unsigned char recipient_pk[crypto_core_ristretto255_BYTES], const unsigned char *m,
    size_t m_len)
{
    unsigned char                      rs[crypto_core_ristretto255_NONREDUCEDSCALARBYTES];
    unsigned char                      ks[crypto_core_ristretto255_SCALARBYTES];
    unsigned char                      kp[crypto_core_ristretto255_BYTES];
    unsigned char                      noise[32];
    sign_state *st = (sign_state *) (void *) st_;

    randombytes_buf(noise, sizeof noise);
    crypto_generichash_init(&st->h, NULL, 0, crypto_core_ristretto255_NONREDUCEDSCALARBYTES);
    crypto_generichash_update(&st->h, (const unsigned char *) "nonce", sizeof "nonce" - 1);
    crypto_generichash_update(&st->h, sender_sk, crypto_core_ristretto255_SCALARBYTES);
    crypto_generichash_update(&st->h, recipient_pk, crypto_core_ristretto255_BYTES);
    crypto_generichash_update(&st->h, noise, sizeof noise);
    crypto_generichash_update(&st->h, m, m_len);
    crypto_generichash_final(&st->h, rs, crypto_core_ristretto255_NONREDUCEDSCALARBYTES);
    crypto_core_ristretto255_scalar_reduce(st->nonce, rs);

    if (crypto_scalarmult_ristretto255_base(st->r, st->nonce) != 0) {
        return -1;
    }
    /* only for clarity - no reduction needed for ristretto */
    memcpy(rs, st->r, crypto_core_ristretto255_BYTES);
    crypto_core_ristretto255_scalar_mul(ks, rs, sender_sk);
    crypto_core_ristretto255_scalar_add(ks, st->nonce, ks);
    if (crypto_scalarmult_ristretto255(kp, ks, recipient_pk) != 0) {
        return -1;
    }

    crypto_generichash_init(&st->h, NULL, 0, SHAREDBYTES);
    crypto_generichash_update(&st->h, (const unsigned char *) "shared_key",
                              sizeof "shared_key" - 1);
    crypto_generichash_update(&st->h, kp, sizeof kp);
    lp_update(&st->h, info, info_len);
    crypto_generichash_final(&st->h, shared_key, SHAREDBYTES);

    crypto_generichash_init(&st->h, NULL, 0, crypto_core_ristretto255_NONREDUCEDSCALARBYTES);
    crypto_generichash_update(&st->h, (const unsigned char *) "sign_key", sizeof "sign_key" - 1);
    crypto_generichash_update(&st->h, st->r, crypto_core_ristretto255_BYTES);
    lp_update(&st->h, info, info_len);

    return 0;
}

int sign_after(
    unsigned char       st_[STATEBYTES],
    unsigned char       sig[SIGNBYTES],
    const unsigned char sender_sk[crypto_core_ristretto255_SCALARBYTES], const unsigned char *c,
    size_t c_len)
{
    unsigned char                      nonreduced[crypto_core_ristretto255_NONREDUCEDSCALARBYTES];
    sign_state *st = (sign_state *) (void *) st_;
    unsigned char *                    r = sig, *s = sig + crypto_core_ristretto255_BYTES;

    crypto_generichash_update(&st->h, c, c_len);
    crypto_generichash_final(&st->h, nonreduced, sizeof nonreduced);
    crypto_core_ristretto255_scalar_reduce(st->challenge, nonreduced);

    crypto_core_ristretto255_scalar_mul(s, st->challenge, sender_sk);
    crypto_core_ristretto255_scalar_sub(s, s, st->nonce);
    memcpy(r, st->r, crypto_core_ristretto255_BYTES);
    sodium_memzero(st, sizeof *st);

    return 0;
}

int verify_before(
    unsigned char       st_[STATEBYTES],
    unsigned char       shared_key[SHAREDBYTES],
    const unsigned char sig[SIGNBYTES], 
    const unsigned char *info, size_t info_len,
    const unsigned char sender_pk[crypto_core_ristretto255_BYTES],
    const unsigned char recipient_sk[crypto_core_ristretto255_BYTES])
{
    unsigned char                      kp[crypto_core_ristretto255_BYTES];
    unsigned char                      rs[crypto_core_ristretto255_NONREDUCEDSCALARBYTES];
    sign_state *st = (sign_state *) (void *) st_;
    const unsigned char *              r = sig, *s = sig + crypto_core_ristretto255_BYTES;

    /* only for clarity - no reduction needed for ristretto */
    memcpy(rs, r, crypto_core_ristretto255_BYTES);
    if (crypto_scalarmult_ristretto255(kp, rs, sender_pk) != 0) {
        return -1;
    }
    crypto_core_ristretto255_add(kp, r, kp);
    if (crypto_scalarmult_ristretto255(kp, recipient_sk, kp) != 0) {
        return -1;
    }

    crypto_generichash_init(&st->h, NULL, 0, SHAREDBYTES);
    crypto_generichash_update(&st->h, (const unsigned char *) "shared_key",
                              sizeof "shared_key" - 1);
    crypto_generichash_update(&st->h, kp, sizeof kp);
    lp_update(&st->h, info, info_len);
    crypto_generichash_final(&st->h, shared_key, SHAREDBYTES);

    crypto_generichash_init(&st->h, NULL, 0, crypto_core_ristretto255_NONREDUCEDSCALARBYTES);
    crypto_generichash_update(&st->h, (const unsigned char *) "sign_key", sizeof "sign_key" - 1);
    crypto_generichash_update(&st->h, r, crypto_core_ristretto255_BYTES);
    lp_update(&st->h, info, info_len);

    return 0;
}

int verify_after(
    unsigned char       st_[STATEBYTES],
    const unsigned char sig[SIGNBYTES],
    const unsigned char sender_pk[crypto_core_ristretto255_BYTES], const unsigned char *c,
    size_t c_len)
{
    unsigned char                      check_expected[crypto_core_ristretto255_BYTES];
    unsigned char                      check_found[crypto_core_ristretto255_BYTES];
    unsigned char                      nonreduced[crypto_core_ristretto255_NONREDUCEDSCALARBYTES];
    sign_state *st = (sign_state *) (void *) st_;
    const unsigned char *              r = sig, *s = sig + crypto_core_ristretto255_BYTES;

    crypto_generichash_update(&st->h, c, c_len);
    crypto_generichash_final(&st->h, nonreduced, sizeof nonreduced);
    crypto_core_ristretto255_scalar_reduce(st->challenge, nonreduced);

    crypto_scalarmult_ristretto255_base(check_expected, s);
    crypto_core_ristretto255_add(check_expected, check_expected, r);

    if (crypto_scalarmult_ristretto255(check_found, st->challenge, sender_pk) != 0) {
        return -1;
    }
    if (sodium_memcmp(check_expected, check_found, crypto_core_ristretto255_SCALARBYTES) != 0) {
        return -1;
    }
    return 0;
}

int verify_public(
    const unsigned char sig[SIGNBYTES],
    const unsigned char *info, size_t info_len,
    const unsigned char sender_pk[crypto_core_ristretto255_BYTES], const unsigned char *c,
    size_t c_len)
{
    sign_state st;
    const unsigned char *             r = sig, *s = sig + crypto_core_ristretto255_BYTES;

    crypto_generichash_init(&st.h, NULL, 0, crypto_core_ristretto255_NONREDUCEDSCALARBYTES);
    crypto_generichash_update(&st.h, (const unsigned char *) "sign_key", sizeof "sign_key" - 1);
    crypto_generichash_update(&st.h, r, crypto_core_ristretto255_BYTES);
    lp_update(&st.h, info, info_len);

    return verify_after((unsigned char *) (void *) &st, sig, sender_pk, c,
                                               c_len);
}

void signcrypt_keygen(unsigned char pk[crypto_core_ristretto255_BYTES],
                                   unsigned char sk[crypto_core_ristretto255_SCALARBYTES])
{
    crypto_core_ristretto255_scalar_random(sk);
    crypto_scalarmult_ristretto255_base(pk, sk);
}

void signcrypt_seed_keygen(unsigned char pk[crypto_core_ristretto255_BYTES],
                                        unsigned char sk[crypto_core_ristretto255_SCALARBYTES],
                                        const unsigned char seed[SEEDBYTES])
{
    crypto_core_ristretto255_scalar_reduce(sk, seed);
    crypto_scalarmult_ristretto255_base(pk, sk);
}


int signcrypt_sign(unsigned char *c,  size_t *c_len,const  unsigned char *info, size_t info_len,const unsigned char *m, size_t m_len, const unsigned char *sender_sk, const unsigned char *recipient_pk){

    unsigned char st[STATEBYTES];
    unsigned char crypt_key[SHAREDBYTES];
    unsigned char sig[SIGNBYTES];
	unsigned char noce[crypto_secretbox_NONCEBYTES];
	crypto_generichash(noce, sizeof noce, info, info_len, NULL, 0);

    if (sign_before(st, crypt_key, info, info_len, sender_sk, recipient_pk, m, m_len) == 0){
		if(crypto_stream_xor(c, m, m_len, noce, crypt_key) == 0){
			if(sign_after(st, sig, sender_sk, c, m_len) == 0) {
				memcpy(c + m_len, sig, sizeof sig);
				*c_len = m_len + SIGNBYTES;
				return 0;
			}
		}
    }
	return 1;
}

int signcrypt_verify(unsigned char *m, size_t *m_len, const unsigned char *info, size_t info_len, const unsigned char *c,  size_t c_len, const unsigned char *sender_pk, const unsigned char *recipient_sk){
    unsigned char st[STATEBYTES];
    unsigned char crypt_key[SHAREDBYTES];
    unsigned char sig[SIGNBYTES];
	unsigned char noce[crypto_secretbox_NONCEBYTES];
	crypto_generichash(noce, sizeof noce, info, info_len, NULL, 0);

	memcpy(sig, c + c_len - SIGNBYTES, SIGNBYTES);
    if (verify_before(st, crypt_key, sig, info, info_len, sender_pk, recipient_sk) == 0){
		c_len -= SIGNBYTES;
		if(crypto_stream_xor(m, c, c_len, noce, crypt_key) == 0){
			if(verify_after(st, sig, sender_pk, c, c_len) == 0) {
				return 0;
			}
		}
    }
    return 1;
}


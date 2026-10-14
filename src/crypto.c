/* wa_crypto.c — OpenSSL-backed primitives (see wa_crypto.h). */
#include "wa_crypto.h"

#include <string.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/sha.h>
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_scalarmult_ed25519.h>

void wa_sha256(const uint8_t *in, size_t ilen, uint8_t out[32]) {
    SHA256(in, ilen, out);
}

int wa_hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *msg,
                   size_t mlen, uint8_t out[32]) {
    unsigned olen = 0;
    if (!key || !msg || !out)
        return -1;
    if (!HMAC(EVP_sha256(), key, (int)klen, msg, mlen, out, &olen) ||
        olen != 32)
        return -1;
    return 0;
}

int wa_hkdf_sha256(uint8_t *okm, size_t okm_len, const uint8_t *ikm,
                   size_t ikm_len, const uint8_t *salt, size_t salt_len,
                   const uint8_t *info, size_t info_len) {
    uint8_t prk[32];
    unsigned prk_len = 0;
    /* Extract: PRK = HMAC-SHA256(salt, IKM). Empty salt => 32 zero bytes. */
    static const uint8_t zero_salt[32] = { 0 };
    if (salt_len == 0) {
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }
    if (!HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len, prk, &prk_len))
        return -1;
    /* Expand (EVP_MAC, OpenSSL 3.0 API). */
    size_t done = 0;
    uint8_t counter = 1;
    uint8_t t[32];
    size_t tlen = 0;
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", (char *)"SHA256", 0),
        OSSL_PARAM_construct_end()
    };
    if (!mac)
        return -1;
    while (done < okm_len) {
        EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
        size_t outl = 0;
        int ok = ctx != NULL &&
                 EVP_MAC_init(ctx, prk, 32, params) &&
                 (tlen == 0 || EVP_MAC_update(ctx, t, tlen)) &&
                 (info_len == 0 || EVP_MAC_update(ctx, info, info_len)) &&
                 EVP_MAC_update(ctx, &counter, 1) &&
                 EVP_MAC_final(ctx, t, &outl, sizeof(t));
        EVP_MAC_CTX_free(ctx);
        if (!ok) {
            EVP_MAC_free(mac);
            return -1;
        }
        tlen = outl;
        size_t take = okm_len - done < tlen ? okm_len - done : tlen;
        memcpy(okm + done, t, take);
        done += take;
        counter++;
        if (counter == 0) {
            EVP_MAC_free(mac);
            return -1; /* >255 blocks, unreasonable */
        }
    }
    EVP_MAC_free(mac);
    return 0;
}

int wa_aes_gcm_encrypt(const uint8_t *pt, size_t ptlen, const uint8_t key[32],
                       const uint8_t iv[12], const uint8_t *aad, size_t aadlen,
                       uint8_t *out, size_t olen) {
    if (olen < ptlen + 16)
        return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;
    int outl = 0, tmplen = 0, rc = -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto out;
    if (aadlen && (EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aadlen) != 1))
        goto out;
    if (EVP_EncryptUpdate(ctx, out, &outl, pt, (int)ptlen) != 1)
        goto out;
    if (EVP_EncryptFinal_ex(ctx, out + outl, &tmplen) != 1)
        goto out;
    outl += tmplen;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out + outl) != 1)
        goto out;
    rc = outl + 16;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rc; /* bytes written, or -1 */
}

int wa_aes_gcm_decrypt(const uint8_t *ct, size_t ctlen, const uint8_t key[32],
                       const uint8_t iv[12], const uint8_t *aad, size_t aadlen,
                       uint8_t *out, size_t olen) {
    if (ctlen < 16 || olen < ctlen - 16)
        return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;
    int outl = 0, tmplen = 0, rc = -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto out;
    if (aadlen && (EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aadlen) != 1))
        goto out;
    if (EVP_DecryptUpdate(ctx, out, &outl, ct, (int)(ctlen - 16)) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                            (void *)(ct + ctlen - 16)) != 1)
        goto out;
    if (EVP_DecryptFinal_ex(ctx, out + outl, &tmplen) != 1)
        goto out; /* auth failure */
    rc = outl + tmplen;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

static int raw_keypair(int nid, const uint8_t priv[32], uint8_t *pub_out,
                       uint8_t *shared_out, const uint8_t *peer) {
    int rc = -1;
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(nid, NULL, priv, 32);
    if (!pkey)
        return -1;
    if (shared_out) {
        EVP_PKEY *peerkey = EVP_PKEY_new_raw_public_key(nid, NULL, peer, 32);
        EVP_PKEY_CTX *ctx = NULL;
        size_t slen = 32;
        if (!peerkey)
            goto out;
        ctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!ctx || EVP_PKEY_derive_init(ctx) != 1 ||
            EVP_PKEY_derive_set_peer(ctx, peerkey) != 1 ||
            EVP_PKEY_derive(ctx, shared_out, &slen) != 1 || slen != 32) {
            EVP_PKEY_free(peerkey);
            EVP_PKEY_CTX_free(ctx);
            goto out;
        }
        EVP_PKEY_free(peerkey);
        EVP_PKEY_CTX_free(ctx);
    }
    if (pub_out) {
        size_t plen = 32;
        if (EVP_PKEY_get_raw_public_key(pkey, pub_out, &plen) != 1 ||
            plen != 32)
            goto out;
    }
    rc = 0;
out:
    EVP_PKEY_free(pkey);
    return rc;
}

int wa_x25519_pub(uint8_t pub_out[32], const uint8_t priv[32]) {
    return raw_keypair(EVP_PKEY_X25519, priv, pub_out, NULL, NULL);
}

int wa_x25519_shared(uint8_t shared_out[32], const uint8_t priv[32],
                     const uint8_t peer_pub[32]) {
    return raw_keypair(EVP_PKEY_X25519, priv, NULL, shared_out, peer_pub);
}

int wa_ed25519_verify(const uint8_t pub[32], const uint8_t *msg, size_t msglen,
                      const uint8_t sig[64]) {
    int rc = -1;
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub,
                                                32);
    EVP_MD_CTX *ctx = NULL;
    if (!pkey)
        return -1;
    ctx = EVP_MD_CTX_new();
    if (!ctx)
        goto out;
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) != 1)
        goto out;
    rc = EVP_DigestVerify(ctx, sig, 64, msg, msglen) == 1 ? 0 : -1;
out:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

/* Montgomery u -> Edwards y = (u-1)/(u+1) mod 2^255-19 (little-endian). */
static int mont_to_edwards_y(const uint8_t u_le[32], uint8_t y_le[32]) {
    int rc = -1;
    BN_CTX *bctx = BN_CTX_new();
    BIGNUM *p = NULL, *u = NULL, *num = NULL, *den = NULL, *inv = NULL, *y = NULL;
    if (!bctx)
        return -1;
    p = BN_new();
    u = BN_lebin2bn(u_le, 32, NULL);
    num = BN_new();
    den = BN_new();
    if (!p || !u || !num || !den)
        goto out;
    /* p = 2^255 - 19 */
    if (!BN_lshift(p, BN_value_one(), 255) || !BN_sub_word(p, 19))
        goto out;
    if (BN_cmp(u, p) >= 0)
        goto out; /* u out of range */
    /* num = u-1, den = u+1 (mod p) */
    if (!BN_copy(num, u) || !BN_sub_word(num, 1))
        goto out;
    if (BN_is_negative(num) && !BN_add(num, num, p))
        goto out;
    if (!BN_copy(den, u) || !BN_add_word(den, 1) || !BN_mod(den, den, p, bctx))
        goto out;
    inv = BN_mod_inverse(NULL, den, p, bctx);
    y = BN_new();
    if (!inv || !y || !BN_mod_mul(y, num, inv, p, bctx))
        goto out;
    if (BN_bn2lebinpad(y, y_le, 32) != 32)
        goto out;
    rc = 0;
out:
    BN_free(p);
    BN_free(u);
    BN_free(num);
    BN_free(den);
    BN_free(inv);
    BN_free(y);
    BN_CTX_free(bctx);
    return rc;
}

int wa_xeddsa_verify(const uint8_t mont_pub[32], const uint8_t *msg,
                     size_t msglen, const uint8_t sig[64]) {
    uint8_t y[32], rsig[64];
    if (!mont_pub || (!msg && msglen) || !sig)
        return -1;
    if (mont_to_edwards_y(mont_pub, y))
        return -1;
    /* curve25519-js curve25519_sign_open: restore A's sign bit from the
     * signature into the Edwards key, and clear it from R. */
    y[31] &= 0x7f;
    y[31] |= sig[63] & 0x80;
    memcpy(rsig, sig, 64);
    rsig[63] &= 0x7f;
    return wa_ed25519_verify(y, msg, msglen, rsig);
}

/* Signal-style sign for Montgomery keys (matches libsignal
 * calculateSignature / curve25519-js curve25519_sign):
 * a = clamp(priv); A = a*B; r = SHA512(a || msg) mod L; R = r*B;
 * h = SHA512(R || A || msg) mod L; s = r + h*a mod L;
 * signature = R || s with A's sign bit OR-ed into byte 63. */
int wa_xeddsa_sign(const uint8_t priv[32], const uint8_t *msg, size_t msglen,
                   uint8_t sig[64]) {
    uint8_t a[32], A[32], rhash[64], r[32], R[32], hram[64], hs[32];
    uint8_t tmp[32];
    crypto_hash_sha512_state st;
    if (!priv || (!msg && msglen) || !sig)
        return -1;
    memcpy(a, priv, 32);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    if (crypto_scalarmult_ed25519_base_noclamp(A, a) != 0)
        return -1;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, a, 32);
    if (msglen)
        crypto_hash_sha512_update(&st, msg, msglen);
    crypto_hash_sha512_final(&st, rhash);
    crypto_core_ed25519_scalar_reduce(r, rhash);
    if (crypto_scalarmult_ed25519_base_noclamp(R, r) != 0)
        return -1;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, R, 32);
    crypto_hash_sha512_update(&st, A, 32);
    if (msglen)
        crypto_hash_sha512_update(&st, msg, msglen);
    crypto_hash_sha512_final(&st, hram);
    crypto_core_ed25519_scalar_reduce(hs, hram);
    crypto_core_ed25519_scalar_mul(tmp, hs, a);
    crypto_core_ed25519_scalar_add(sig + 32, tmp, r);
    memcpy(sig, R, 32);
    sig[63] |= A[31] & 0x80;
    return 0;
}

int wa_pbkdf2_sha256(const char *pass, const uint8_t *salt, size_t saltlen,
                     unsigned iters, uint8_t *out, size_t olen) {
    if (!pass || !salt || !out || !olen)
        return -1;
    if (PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass), salt, (int)saltlen,
                          (int)iters, EVP_sha256(), (int)olen, out) != 1)
        return -1;
    return 0;
}

int wa_aes_ctr_encrypt(const uint8_t *in, size_t ilen, const uint8_t key[32],
                       const uint8_t iv[16], uint8_t *out, size_t olen) {
    EVP_CIPHER_CTX *ctx;
    int outl = 0, tmplen = 0;
    if (!in || !out || olen < ilen)
        return -1;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, out, &outl, in, (int)ilen) != 1 ||
        EVP_EncryptFinal_ex(ctx, out + outl, &tmplen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return outl + tmplen;
}

void wa_crockford5(const uint8_t in[5], char out[9]) {
    static const char *ABC = "123456789ABCDEFGHJKLMNPQRSTVWXYZ";
    uint32_t value = 0;
    int bits = 0, n = 0;
    for (int i = 0; i < 5; i++) {
        value = (value << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            out[n++] = ABC[(value >> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    out[n] = '\0';
}

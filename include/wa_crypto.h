/* wa_crypto.h — primitives backing the Noise handshake.
 *
 * Mirrors Baileys src/Utils/crypto.ts (AES-256-GCM with suffixed tag,
 * X25519 via libsignal curve, Ed25519 verify, HKDF-SHA256) using OpenSSL.
 */
#ifndef WA_CRYPTO_H
#define WA_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void wa_sha256(const uint8_t *in, size_t ilen, uint8_t out[32]);

/* RFC 5869 HKDF-SHA256: PRK=HMAC(salt,ikm); expand with info. */
int wa_hkdf_sha256(uint8_t *okm, size_t okm_len, const uint8_t *ikm,
                   size_t ikm_len, const uint8_t *salt, size_t salt_len,
                   const uint8_t *info, size_t info_len);

/* AES-256-GCM, 12-byte IV, 16-byte tag suffixed to ciphertext. */
int wa_aes_gcm_encrypt(const uint8_t *pt, size_t ptlen, const uint8_t key[32],
                       const uint8_t iv[12], const uint8_t *aad, size_t aadlen,
                       uint8_t *out, size_t olen);
/* Returns 0 on success, -1 on auth failure. */
int wa_aes_gcm_decrypt(const uint8_t *ct, size_t ctlen, const uint8_t key[32],
                       const uint8_t iv[12], const uint8_t *aad, size_t aadlen,
                       uint8_t *out, size_t olen);

/* X25519. Returns 0 on success. */
int wa_x25519_pub(uint8_t pub_out[32], const uint8_t priv[32]);
int wa_x25519_shared(uint8_t shared_out[32], const uint8_t priv[32],
                     const uint8_t peer_pub[32]);

/* Ed25519 verify (for Noise cert chain). 0 = valid, -1 = invalid/error. */
int wa_ed25519_verify(const uint8_t pub[32], const uint8_t *msg, size_t msglen,
                      const uint8_t sig[64]);

/* XEdDSA verify (Signal/Curve.verify semantics): converts a Montgomery
 * (Curve25519) public key to Edwards y=(u-1)/(u+1), then Ed25519-verifies.
 * This is what WhatsApp cert chains and device signatures use. */
int wa_xeddsa_verify(const uint8_t mont_pub[32], const uint8_t *msg,
                     size_t msglen, const uint8_t sig[64]);

/* XEdDSA sign (Signal/Curve.sign semantics) with a Montgomery private key.
 * Deterministic; byte-identical to libsignal's calculateSignature. */
int wa_xeddsa_sign(const uint8_t priv[32], const uint8_t *msg, size_t msglen,
                   uint8_t sig[64]);

/* HMAC-SHA256. out must hold 32 bytes. */
int wa_hmac_sha256(const uint8_t *key, size_t klen, const uint8_t *msg,
                   size_t mlen, uint8_t out[32]);

/* PBKDF2-SHA256 (for pairing-code key derivation). */
int wa_pbkdf2_sha256(const char *pass, const uint8_t *salt, size_t saltlen,
                     unsigned iters, uint8_t *out, size_t olen);

/* AES-256-CTR encrypt (for pairing ephemeral-pub wrapping). */
int wa_aes_ctr_encrypt(const uint8_t *in, size_t ilen, const uint8_t key[32],
                       const uint8_t iv[16], uint8_t *out, size_t olen);

/* AES-256-CBC encrypt (for Signal WhisperMessage payloads). PKCS#7 padding
 * is handled by OpenSSL; out must hold ilen+16. Returns bytes or -1. */
int wa_aes_cbc_encrypt(const uint8_t *in, size_t ilen, const uint8_t key[32],
                       const uint8_t iv[16], uint8_t *out, size_t olen);

/* AES-256-CBC decrypt (Signal WhisperMessage payloads). PKCS#7 padding is
 * removed by OpenSSL; out must hold at least ctlen bytes. Returns bytes or
 * -1 on padding/auth failure. */
int wa_aes_cbc_decrypt(const uint8_t *in, size_t ilen, const uint8_t key[32],
                       const uint8_t iv[16], uint8_t *out, size_t olen);

/* Baileys bytesToCrockford (custom alphabet, 5 bytes -> 8 chars + NUL). */
void wa_crockford5(const uint8_t in[5], char out[9]);

#ifdef __cplusplus
}
#endif

#endif /* WA_CRYPTO_H */

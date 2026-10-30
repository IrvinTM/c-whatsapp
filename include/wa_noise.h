/* wa_noise.h — Noise XX handshake wrapper (Phase 3, OpenSSL).
 *
 * Mirrors Baileys makeNoiseHandler (src/Utils/noise-handler.ts):
 * hash/salt/key mixing with SHA256 + HKDF-SHA256, AES-256-GCM with the
 * 12-byte counter IV, transport state with split read/write counters,
 * intro-header + 3-byte frame framing, and the handshake step order
 * (server-ephemeral -> static -> cert payload -> client static).
 * Cert-chain protobuf parsing + login/registration stanzas are Phase 4.
 */
#ifndef WA_NOISE_H
#define WA_NOISE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WA_NOISE_KEY_LEN 32
#define WA_NOISE_HEADER_LEN 4
#define WA_NOISE_TAG_LEN 16
#define WA_CERT_SERIAL 0

/* "Noise_XX_25519_AESGCM_SHA256" + 4 NULs = 32 bytes (Baileys NOISE_MODE). */
extern const char WA_NOISE_MODE[32];
/* { 'W', 'A', 6, DICT_VERSION } (Baileys NOISE_WA_HEADER). */
extern const uint8_t WA_NOISE_WA_HEADER[4];
/* WhatsApp long-term cert key (Baileys WA_CERT_DETAILS.PUBLIC_KEY). */
extern const uint8_t WA_CERT_PUBKEY[32];

typedef struct {
    uint8_t e_priv[WA_NOISE_KEY_LEN];
    uint8_t e_pub[WA_NOISE_KEY_LEN];
    uint8_t server_eph[WA_NOISE_KEY_LEN];
    int have_server_eph;
    uint8_t header[WA_NOISE_HEADER_LEN];
    uint8_t routing_info[64];
    size_t routing_info_len;
    uint8_t hash[32];
    uint8_t salt[32];
    uint8_t enc_key[32];
    uint8_t dec_key[32];
    uint32_t counter; /* handshake-phase shared counter */
    uint8_t t_enc[32];
    uint8_t t_dec[32];
    uint32_t read_counter;
    uint32_t write_counter;
    int transport; /* handshake_done */
    int intro_sent;
    uint8_t *inbuf;
    size_t inlen;
    size_t incap;
} wa_noise_t;

/* Frame callback for wa_noise_feed. Return 0 to continue, !=0 aborts. */
typedef int (*wa_frame_cb)(const uint8_t *frame, size_t len, void *user);

void wa_noise_init(wa_noise_t *n, const uint8_t ephemeral_priv[32],
                   const uint8_t header[4]);
void wa_noise_free(wa_noise_t *n);

/* Mix raw bytes into the handshake hash (authenticate). */
int wa_noise_authenticate(wa_noise_t *n, const uint8_t *data, size_t len);

/* Handshake-phase encrypt/decrypt. Returns bytes written or -1. */
int wa_noise_encrypt(wa_noise_t *n, const uint8_t *in, size_t ilen,
                     uint8_t *out, size_t olen);
int wa_noise_decrypt(wa_noise_t *n, const uint8_t *in, size_t ilen,
                     uint8_t *out, size_t olen);

/* HKDF-mix a DH shared secret into salt/keys (mixIntoKey). */
int wa_noise_mix_key(wa_noise_t *n, const uint8_t *secret, size_t slen);

/* Derive transport keys from empty input (finishInit). */
int wa_noise_finish_init(wa_noise_t *n);

/*
 * Handshake steps mirroring Baileys processHandshake (protobuf-free):
 *  1. wa_noise_mix_server_ephemeral: authenticate(eph) + mix DH(e,s_eph)
 *  2. decrypt server static with wa_noise_decrypt, then
 *     wa_noise_mix_static: mix DH(e, static)
 *  3. decrypt cert payload with wa_noise_decrypt (protobuf in Phase 4)
 *  4. wa_noise_encrypt_static: encrypt noise pub + mix DH(noise,s_eph)
 */
int wa_noise_mix_server_ephemeral(wa_noise_t *n, const uint8_t server_eph[32]);
int wa_noise_mix_static(wa_noise_t *n, const uint8_t static_pub[32]);
int wa_noise_encrypt_static(wa_noise_t *n, const uint8_t noise_pub[32],
                            const uint8_t noise_priv[32], uint8_t out[48]);

/* Transport encrypt/decrypt (post-finish_init). Returns bytes or -1. */
int wa_noise_transport_encrypt(wa_noise_t *n, const uint8_t *in, size_t ilen,
                               uint8_t *out, size_t olen);
int wa_noise_transport_decrypt(wa_noise_t *n, const uint8_t *in, size_t ilen,
                               uint8_t *out, size_t olen);

/* Frame encode (intro header once, then 3-byte length prefix).
 * Returns bytes written or -1 (needs intro+3+plen(+16 if transport)). */
int wa_noise_encode_frame(wa_noise_t *n, const uint8_t *payload,
                          size_t plen, uint8_t *out, size_t olen,
                          size_t *written);

/* Feed received bytes; emits frames via cb (decrypted if transport).
 * Returns frames emitted, or -1 on decrypt/alloc error. */
/* 1 if a complete frame is already buffered (left behind when a callback
 * stopped the previous feed). Feed NULL/0 to process it. */
int wa_noise_pending(const wa_noise_t *n);
int wa_noise_feed(wa_noise_t *n, const uint8_t *data, size_t len,
                  wa_frame_cb cb, void *user);

#ifdef __cplusplus
}
#endif

#endif /* WA_NOISE_H */

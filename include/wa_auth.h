/* wa_auth.h — session credential store.
 *
 * Mirrors Baileys `useMultiFileAuthState` / `creds.update` at v0.1 scope:
 * a single creds.json inside the auth dir holds the Noise + identity keys
 * and the linked-device identity (me). Signal records (sessions, prekeys,
 * sender keys) get their own files in Phase 5.
 *
 * NOTE: public halves are X25519-derived from the private halves (as in
 * Baileys); XEdDSA prekey signing arrives with the Signal layer (Phase 5).
 */
#ifndef WA_AUTH_H
#define WA_AUTH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WA_KEY_LEN 32
#define WA_SIG_LEN 64
#define WA_ADV_LEN 32
#define WA_JID_MAX 128
#define WA_NAME_MAX 64
#define WA_ROUTE_MAX 64
#define WA_PLATFORM_MAX 64
#define WA_ACCOUNT_DETAILS_MAX 256

/* Companion account identity established at pairing (ADVSignedDeviceIdentity
 * with our device signature). Persisted for future session use. */
typedef struct {
    uint8_t details[WA_ACCOUNT_DETAILS_MAX];
    size_t details_len;
    uint8_t account_sig_key[WA_KEY_LEN];
    uint8_t account_sig[WA_SIG_LEN];
    uint8_t device_sig[WA_SIG_LEN];
    uint32_t key_index;
    int present;
} wa_account_t;

typedef struct {
    uint8_t noise_priv[WA_KEY_LEN];
    uint8_t noise_pub[WA_KEY_LEN];
    uint8_t ident_priv[WA_KEY_LEN];
    uint8_t ident_pub[WA_KEY_LEN];
    uint8_t pre_priv[WA_KEY_LEN];
    uint8_t pre_pub[WA_KEY_LEN];
    uint8_t pre_sig[WA_SIG_LEN];
    uint32_t pre_id;
    uint32_t registration_id;
    uint8_t adv_secret[WA_ADV_LEN];
    uint8_t routing_info[WA_ROUTE_MAX];
    size_t routing_info_len;
    char me_id[WA_JID_MAX];
    char me_lid[WA_JID_MAX];
    char me_name[WA_NAME_MAX];
    char platform[WA_PLATFORM_MAX];
    uint32_t next_prekey_id;
    uint32_t first_unuploaded_prekey_id;
    wa_account_t account;
    /* pairing-code flow state (persisted like Baileys creds). */
    uint8_t pairing_eph_priv[WA_KEY_LEN];
    uint8_t pairing_eph_pub[WA_KEY_LEN];
    char pairing_code[16];
    int registered;
} wa_creds_t;

void wa_creds_init(wa_creds_t *c);
int wa_creds_generate(wa_creds_t *c); /* random keys + registration id */
/* Fresh pairing ephemeral + 8-char code for --pair (saves caller to persist). */
int wa_creds_gen_pairing(wa_creds_t *c);

/* 0 = loaded, 1 = no session yet, -1 = error. */
int wa_auth_load(wa_creds_t *c, const char *dir);
int wa_auth_save(const wa_creds_t *c, const char *dir);

/* base64 helpers (standard alphabet, padded). */
int wa_b64_encode(const uint8_t *in, size_t ilen, char *out, size_t olen);
int wa_b64_decode(const char *in, uint8_t *out, size_t olen, size_t *written);

#ifdef __cplusplus
}
#endif

#endif /* WA_AUTH_H */

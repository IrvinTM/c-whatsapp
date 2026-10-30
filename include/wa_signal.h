/* wa_signal.h — Signal (libsignal v3) sessions for WhatsApp E2EE.
 *
 * Ports the libsignal-protocol JS used by Baileys:
 *   SessionBuilder.initSession (initiator + responder X3DH),
 *   SessionCipher.encrypt / decryptWithSessions (Double Ratchet),
 *   ChainKey fillMessageKeys + RootKey.createChain, all under the
 *   "WhisperText"/"WhisperRatchet"/"WhisperMessageKeys" HKDF infos.
 *
 * Sessions are keyed by the peer's device JID (Signal address) and persisted
 * to <auth_dir>/signal.tsv; our one-time prekeys (id -> private half) live in
 * <auth_dir>/prekeys.tsv so inbound X3DH can complete after a restart.
 */
#ifndef WA_SIGNAL_H
#define WA_SIGNAL_H

#include "wa_auth.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WA_SIG_ADDR_MAX 160
#define WA_SIG_MAX_SESSIONS 128
#define WA_SIG_MAX_CHAINS 6
#define WA_SIG_MAX_SKIPPED 32
#define WA_SIG_MAX_OPK 64

/* Prekey bundle as returned by the server `encrypt` iq (used to start an
 * outgoing session). Public halves only. */
typedef struct {
    uint8_t identity[32];
    uint8_t spk[32];
    uint32_t spk_id;
    uint8_t spk_sig[64];
    uint8_t opk[32];
    uint32_t opk_id;
    int have_opk;
    uint32_t reg_id;
} wa_bundle_t;

typedef struct {
    uint32_t idx;
    uint8_t key[32];
} wa_sig_skip_t;

typedef struct {
    uint8_t peer_key[33]; /* remote ephemeral (recv) or our pub (send) */
    int is_sending;
    int has_key;
    uint8_t chain_key[32];
    uint32_t next_counter;
    wa_sig_skip_t skipped[WA_SIG_MAX_SKIPPED];
    int n_skipped;
} wa_sig_chain_t;

typedef struct {
    int used;
    char addr[WA_SIG_ADDR_MAX];
    uint8_t remote_identity[33];
    uint8_t root_key[32];
    uint8_t dhs_priv[32]; /* our current ratchet key pair */
    uint8_t dhs_pub[33];
    uint8_t dhr[33]; /* last remote ephemeral */
    int have_dhs;
    int have_dhr;
    uint32_t previous_counter;
    uint8_t base_key[33]; /* base key of the session (X3DH) */
    wa_sig_chain_t chains[WA_SIG_MAX_CHAINS];
    int n_chains;
    /* pending outgoing prekey message (initiator, before first send) */
    int pending_prekey;
    uint32_t pending_spk_id;
    uint32_t pending_opk_id;
    int pending_have_opk;
} wa_sig_session_t;

typedef struct {
    uint32_t id;
    uint8_t priv[32];
} wa_sig_opk_t;

typedef struct {
    char dir[WA_SIG_ADDR_MAX];
    const wa_creds_t *creds;
    wa_sig_session_t sessions[WA_SIG_MAX_SESSIONS];
    int n_sessions;
    wa_sig_opk_t opks[WA_SIG_MAX_OPK];
    int n_opk;
    uint32_t next_prekey_id;
} wa_sig_t;

/* dir = auth dir (sessions + prekeys). creds supplies our identity/signed
 * prekey and must outlive the store. */
int wa_sig_init(wa_sig_t *s, const char *dir, const wa_creds_t *creds);
/* Loads sessions + prekeys if the files exist (missing files are fine). */
int wa_sig_load(wa_sig_t *s);
int wa_sig_save(wa_sig_t *s);
int wa_sig_save_prekeys(wa_sig_t *s);

/* Store a one-time prekey private half (used when a responder X3DH needs it). */
int wa_sig_add_opk(wa_sig_t *s, uint32_t id, const uint8_t priv[32]);

/* Generate n fresh one-time prekeys starting at start_id; stores the private
 * halves and fills ids[] + pubs[][32] (public, no 0x05 prefix) for upload. */
int wa_sig_gen_opks(wa_sig_t *s, uint32_t start_id, int n, uint32_t *ids,
                    uint8_t (*pubs)[32]);

int wa_sig_has_session(const wa_sig_t *s, const char *addr);
int wa_sig_session_confirmed(const wa_sig_t *s, const char *addr);

/* Decrypt an inbound <enc> body. type = "pkmsg" (PreKeyWhisperMessage) or
 * "msg" (WhisperMessage). On success returns 0 and *out = malloc'd plaintext
 * (WAMessage protobuf, random padding already stripped). */
int wa_sig_decrypt(wa_sig_t *s, const char *addr, const char *type,
                   const uint8_t *body, size_t blen, uint8_t **out,
                   size_t *outlen);

/* Encrypt on an existing session; produces a "msg" body. Returns -ENOENT when
 * there is no usable sending chain. *out is malloc'd. */
int wa_sig_encrypt(wa_sig_t *s, const char *addr, const uint8_t *pt,
                   size_t ptlen, uint8_t **out, size_t *outlen);

/* Initiator: create a session with a peer bundle and produce the first
 * (pkmsg) message; the session is stored so replies can be decrypted. */
int wa_sig_encrypt_pkmsg(wa_sig_t *s, const char *addr, const wa_bundle_t *b,
                         const uint8_t *pt, size_t ptlen, uint8_t **out,
                         size_t *outlen);

/* Strip Baileys writeRandomPadMax16 padding: last byte is pad length. */
int wa_sig_unpad(const uint8_t *in, size_t inlen, const uint8_t **out,
                 size_t *outlen);

#ifdef __cplusplus
}
#endif

#endif /* WA_SIGNAL_H */

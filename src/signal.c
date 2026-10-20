/* wa_signal.c — Signal sessions (see wa_signal.h). */
#define _POSIX_C_SOURCE 200809L

#include "wa_signal.h"
#include "wa_crypto.h"
#include "wa_pb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

/* ---------------- small helpers ---------------- */

static void to33(uint8_t out[33], const uint8_t p32[32]) {
    out[0] = 5;
    memcpy(out + 1, p32, 32);
}

static int b64e(const uint8_t *in, size_t len, char *out, size_t outcap) {
    return wa_b64_encode(in, len, out, outcap);
}

static const uint8_t *own_identity33(const wa_sig_t *s, uint8_t buf[33]) {
    to33(buf, s->creds->ident_pub);
    return buf;
}

/* ---------------- chain/session helpers ---------------- */

static wa_sig_chain_t *chain_by_peer(wa_sig_session_t *ss, const uint8_t peer[33]) {
    for (int i = 0; i < ss->n_chains; i++)
        if (!memcmp(ss->chains[i].peer_key, peer, 33))
            return &ss->chains[i];
    return NULL;
}

static wa_sig_chain_t *add_chain(wa_sig_session_t *ss, const uint8_t peer[33],
                                 int sending, const uint8_t chain_key[32]) {
    wa_sig_chain_t *ch;
    if (ss->n_chains >= WA_SIG_MAX_CHAINS) {
        /* drop the oldest (index 0) */
        memmove(&ss->chains[0], &ss->chains[1],
                sizeof(ss->chains[0]) * (WA_SIG_MAX_CHAINS - 1));
        ss->n_chains--;
    }
    ch = &ss->chains[ss->n_chains++];
    memset(ch, 0, sizeof(*ch));
    memcpy(ch->peer_key, peer, 33);
    ch->is_sending = sending;
    ch->has_key = 1;
    memcpy(ch->chain_key, chain_key, 32);
    ch->next_counter = 0;
    return ch;
}

static void remove_chain(wa_sig_session_t *ss, wa_sig_chain_t *ch) {
    ptrdiff_t idx = ch - ss->chains;
    if (idx < 0 || idx >= ss->n_chains)
        return;
    memmove(&ss->chains[idx], &ss->chains[idx + 1],
            sizeof(ss->chains[0]) * (ss->n_chains - idx - 1));
    ss->n_chains--;
}

static void skip_store(wa_sig_chain_t *ch, uint32_t idx, const uint8_t key[32]) {
    if (ch->n_skipped >= WA_SIG_MAX_SKIPPED) {
        memmove(&ch->skipped[0], &ch->skipped[1],
                sizeof(ch->skipped[0]) * (WA_SIG_MAX_SKIPPED - 1));
        ch->n_skipped--;
    }
    ch->skipped[ch->n_skipped].idx = idx;
    memcpy(ch->skipped[ch->n_skipped].key, key, 32);
    ch->n_skipped++;
}

/* Derive the message key at idx, advancing the chain and stashing skipped
 * keys for indices we pass over (out-of-order tolerance). */
static int chain_message_key(wa_sig_chain_t *ch, uint32_t idx, uint8_t out[32]) {
    static const uint8_t one = 1, two = 2;
    for (int i = 0; i < ch->n_skipped; i++) {
        if (ch->skipped[i].idx == idx) {
            memcpy(out, ch->skipped[i].key, 32);
            memmove(&ch->skipped[i], &ch->skipped[i + 1],
                    sizeof(ch->skipped[0]) * (ch->n_skipped - i - 1));
            ch->n_skipped--;
            return 0;
        }
    }
    if (!ch->has_key || idx < ch->next_counter)
        return -1;
    while (ch->next_counter <= idx) {
        uint8_t mk[32], nxt[32];
        if (wa_hmac_sha256(ch->chain_key, 32, &one, 1, mk) ||
            wa_hmac_sha256(ch->chain_key, 32, &two, 1, nxt))
            return -1;
        memcpy(ch->chain_key, nxt, 32);
        if (ch->next_counter < idx)
            skip_store(ch, ch->next_counter, mk);
        else
            memcpy(out, mk, 32);
        ch->next_counter++;
    }
    return 0;
}

static int derive(char *out, size_t outlen, const uint8_t *ikm, size_t ikmlen,
                  const uint8_t salt[32], const char *info) {
    return wa_hkdf_sha256((uint8_t *)out, outlen, ikm, ikmlen, salt, 32,
                          (const uint8_t *)info, strlen(info));
}

/* rootKey.createChain(remote, ourRatchet): newRoot||chainKey from DH. */
static int calc_ratchet(wa_sig_session_t *ss, const uint8_t remote[33],
                        int sending) {
    uint8_t shared[32], m[64];
    if (wa_x25519_shared(shared, ss->dhs_priv, remote + 1))
        return -1;
    if (derive((char *)m, 64, shared, 32, ss->root_key, "WhisperRatchet"))
        return -1;
    add_chain(ss, sending ? ss->dhs_pub : remote, sending, m + 32);
    memcpy(ss->root_key, m, 32);
    return 0;
}

static int maybe_step_ratchet(wa_sig_session_t *ss, const uint8_t remote[33],
                              uint32_t previous_counter) {
    wa_sig_chain_t *prev;
    if (chain_by_peer(ss, remote))
        return 0;
    prev = ss->have_dhr ? chain_by_peer(ss, ss->dhr) : NULL;
    if (prev) {
        if (prev->has_key && previous_counter >= prev->next_counter) {
            uint8_t mk[32];
            while (prev->next_counter <= previous_counter) {
                if (chain_message_key(prev, prev->next_counter, mk))
                    break;
            }
        }
        prev->has_key = 0; /* close old receiving chain */
    }
    if (calc_ratchet(ss, remote, 0))
        return -1;
    if (ss->have_dhs) {
        wa_sig_chain_t *sc = chain_by_peer(ss, ss->dhs_pub);
        if (sc) {
            ss->previous_counter = sc->next_counter;
            remove_chain(ss, sc);
        }
    }
    {
        uint8_t priv[32], pub[32];
        if (RAND_bytes(priv, 32) != 1 || wa_x25519_pub(pub, priv))
            return -1;
        memcpy(ss->dhs_priv, priv, 32);
        to33(ss->dhs_pub, pub);
        ss->have_dhs = 1;
    }
    if (calc_ratchet(ss, remote, 1))
        return -1;
    memcpy(ss->dhr, remote, 33);
    ss->have_dhr = 1;
    return 0;
}

/* ---------------- store ---------------- */

int wa_sig_init(wa_sig_t *s, const char *dir, const wa_creds_t *creds) {
    if (!s || !creds)
        return -1;
    memset(s, 0, sizeof(*s));
    snprintf(s->dir, sizeof(s->dir), "%s", dir ? dir : "auth_info");
    s->creds = creds;
    s->next_prekey_id = creds->next_prekey_id ? creds->next_prekey_id : 1;
    return 0;
}

static void trim_nl(char *s) {
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

int wa_sig_add_opk(wa_sig_t *s, uint32_t id, const uint8_t priv[32]) {
    if (!s)
        return -1;
    if (s->n_opk >= WA_SIG_MAX_OPK) {
        memmove(&s->opks[0], &s->opks[1],
                sizeof(s->opks[0]) * (WA_SIG_MAX_OPK - 1));
        s->n_opk--;
    }
    s->opks[s->n_opk].id = id;
    memcpy(s->opks[s->n_opk].priv, priv, 32);
    s->n_opk++;
    return 0;
}

static int opk_get(const wa_sig_t *s, uint32_t id, uint8_t priv[32]) {
    for (int i = 0; i < s->n_opk; i++)
        if (s->opks[i].id == id) {
            memcpy(priv, s->opks[i].priv, 32);
            return 0;
        }
    return -1;
}

static void opk_remove(wa_sig_t *s, uint32_t id) {
    for (int i = 0; i < s->n_opk; i++) {
        if (s->opks[i].id == id) {
            memmove(&s->opks[i], &s->opks[i + 1],
                    sizeof(s->opks[0]) * (s->n_opk - i - 1));
            s->n_opk--;
            return;
        }
    }
}

int wa_sig_gen_opks(wa_sig_t *s, uint32_t start_id, int n, uint32_t *ids,
                    uint8_t (*pubs)[32]) {
    int made = 0;
    for (int i = 0; i < n; i++) {
        uint8_t priv[32], pub[32];
        uint32_t id = start_id + (uint32_t)i;
        if (RAND_bytes(priv, 32) != 1 || wa_x25519_pub(pub, priv))
            return -1;
        wa_sig_add_opk(s, id, priv);
        if (ids)
            ids[i] = id;
        if (pubs)
            memcpy(pubs[i], pub, 32);
        made++;
    }
    if (s->next_prekey_id <= start_id + (uint32_t)n)
        s->next_prekey_id = start_id + (uint32_t)n;
    return made == n ? 0 : -1;
}

static wa_sig_session_t *session_find(wa_sig_t *s, const char *addr) {
    for (int i = 0; i < s->n_sessions; i++)
        if (s->sessions[i].used && !strcmp(s->sessions[i].addr, addr))
            return &s->sessions[i];
    return NULL;
}

static wa_sig_session_t *session_create(wa_sig_t *s, const char *addr) {
    wa_sig_session_t *ss = session_find(s, addr);
    if (ss)
        return ss;
    if (s->n_sessions >= WA_SIG_MAX_SESSIONS)
        return NULL;
    ss = &s->sessions[s->n_sessions++];
    memset(ss, 0, sizeof(*ss));
    ss->used = 1;
    snprintf(ss->addr, sizeof(ss->addr), "%s", addr);
    return ss;
}

/* ---------------- persistence ---------------- */

static int save_prekeys(wa_sig_t *s) {
    char path[WA_SIG_ADDR_MAX + 32];
    FILE *f;
    snprintf(path, sizeof(path), "%s/prekeys.tsv", s->dir);
    f = fopen(path, "w");
    if (!f)
        return -1;
    for (int i = 0; i < s->n_opk; i++) {
        char b[64];
        b64e(s->opks[i].priv, 32, b, sizeof(b));
        fprintf(f, "%u\t%s\n", s->opks[i].id, b);
    }
    fclose(f);
    return 0;
}

int wa_sig_save_prekeys(wa_sig_t *s) {
    return s ? save_prekeys(s) : -1;
}

static void load_prekeys(wa_sig_t *s) {
    char path[WA_SIG_ADDR_MAX + 32], *line = NULL;
    size_t ll = 0;
    ssize_t n;
    FILE *f;
    snprintf(path, sizeof(path), "%s/prekeys.tsv", s->dir);
    f = fopen(path, "r");
    if (!f)
        return;
    while ((n = getline(&line, &ll, f)) >= 0) {
        char *tab, *id_s;
        uint8_t priv[32];
        size_t w = 0;
        trim_nl(line);
        if (!line[0])
            continue;
        tab = strchr(line, '\t');
        if (!tab)
            continue;
        *tab = '\0';
        id_s = line;
        if (wa_b64_decode(tab + 1, priv, 32, &w) || w != 32)
            continue;
        wa_sig_add_opk(s, (uint32_t)strtoul(id_s, NULL, 10), priv);
    }
    free(line);
    fclose(f);
}

static int save_sessions(wa_sig_t *s) {
    char path[WA_SIG_ADDR_MAX + 32];
    FILE *f;
    snprintf(path, sizeof(path), "%s/signal.tsv", s->dir);
    f = fopen(path, "w");
    if (!f)
        return -1;
    for (int i = 0; i < s->n_sessions; i++) {
        wa_sig_session_t *ss = &s->sessions[i];
        char rid[64], rk[64], dp[64], dpu[64], dhr[64], bk[64];
        if (!ss->used)
            continue;
        b64e(ss->remote_identity, 33, rid, sizeof(rid));
        b64e(ss->root_key, 32, rk, sizeof(rk));
        b64e(ss->dhs_priv, 32, dp, sizeof(dp));
        b64e(ss->dhs_pub, 33, dpu, sizeof(dpu));
        b64e(ss->dhr, 33, dhr, sizeof(dhr));
        b64e(ss->base_key, 33, bk, sizeof(bk));
        fprintf(f, "%s\t%s\t%s\t%s\t%s\t%s\t%u\t%d\t%d\t%s\t%d",
                ss->addr, rid, rk, dp, dpu, dhr, ss->previous_counter,
                ss->have_dhs, ss->have_dhr, bk, ss->n_chains);
        for (int c = 0; c < ss->n_chains; c++) {
            wa_sig_chain_t *ch = &ss->chains[c];
            char pk[64], ck[64];
            b64e(ch->peer_key, 33, pk, sizeof(pk));
            b64e(ch->chain_key, 32, ck, sizeof(ck));
            fprintf(f, "\t%d\t%s\t%d\t%s\t%u\t%d", ch->is_sending, pk,
                    ch->has_key, ck, ch->next_counter, ch->n_skipped);
            if (!ch->n_skipped) {
                fprintf(f, "\t-");
            } else {
                fprintf(f, "\t");
                for (int k = 0; k < ch->n_skipped; k++) {
                    char sk[64];
                    b64e(ch->skipped[k].key, 32, sk, sizeof(sk));
                    fprintf(f, "%s%u:%s", k ? "|" : "", ch->skipped[k].idx, sk);
                }
            }
        }
        fprintf(f, "\n");
    }
    fclose(f);
    return 0;
}

static void load_sessions(wa_sig_t *s) {
    char path[WA_SIG_ADDR_MAX + 32], *line = NULL;
    size_t ll = 0;
    ssize_t n;
    FILE *f;
    snprintf(path, sizeof(path), "%s/signal.tsv", s->dir);
    f = fopen(path, "r");
    if (!f)
        return;
    while ((n = getline(&line, &ll, f)) >= 0) {
        char *save = NULL, *tok;
        wa_sig_session_t *ss;
        size_t w = 0;
        int nch, ci;
        trim_nl(line);
        if (!line[0])
            continue;
        ss = session_create(s, "");
        if (!ss)
            break;
        tok = strtok_r(line, "\t", &save);
        if (!tok)
            continue;
        snprintf(ss->addr, sizeof(ss->addr), "%s", tok);
        tok = strtok_r(NULL, "\t", &save);
        if (!tok || wa_b64_decode(tok, ss->remote_identity, 33, &w) || w != 33)
            continue;
        tok = strtok_r(NULL, "\t", &save);
        if (!tok || wa_b64_decode(tok, ss->root_key, 32, &w) || w != 32)
            continue;
        tok = strtok_r(NULL, "\t", &save);
        if (!tok || wa_b64_decode(tok, ss->dhs_priv, 32, &w) || w != 32)
            continue;
        tok = strtok_r(NULL, "\t", &save);
        if (!tok || wa_b64_decode(tok, ss->dhs_pub, 33, &w) || w != 33)
            continue;
        tok = strtok_r(NULL, "\t", &save);
        if (!tok || wa_b64_decode(tok, ss->dhr, 33, &w) || w != 33)
            continue;
        tok = strtok_r(NULL, "\t", &save);
        if (tok)
            ss->previous_counter = (uint32_t)strtoul(tok, NULL, 10);
        tok = strtok_r(NULL, "\t", &save);
        if (tok)
            ss->have_dhs = atoi(tok);
        tok = strtok_r(NULL, "\t", &save);
        if (tok)
            ss->have_dhr = atoi(tok);
        tok = strtok_r(NULL, "\t", &save);
        if (!tok || wa_b64_decode(tok, ss->base_key, 33, &w) || w != 33)
            continue;
        tok = strtok_r(NULL, "\t", &save);
        nch = tok ? atoi(tok) : 0;
        for (ci = 0; ci < nch && ci < WA_SIG_MAX_CHAINS; ci++) {
            wa_sig_chain_t *ch = &ss->chains[ss->n_chains];
            char *sk_save = NULL, *sk_tok;
            memset(ch, 0, sizeof(*ch));
            tok = strtok_r(NULL, "\t", &save);
            if (!tok)
                break;
            ch->is_sending = atoi(tok);
            tok = strtok_r(NULL, "\t", &save);
            if (!tok || wa_b64_decode(tok, ch->peer_key, 33, &w) || w != 33)
                break;
            tok = strtok_r(NULL, "\t", &save);
            if (tok)
                ch->has_key = atoi(tok);
            tok = strtok_r(NULL, "\t", &save);
            if (!tok || wa_b64_decode(tok, ch->chain_key, 32, &w) || w != 32)
                break;
            tok = strtok_r(NULL, "\t", &save);
            if (tok)
                ch->next_counter = (uint32_t)strtoul(tok, NULL, 10);
            tok = strtok_r(NULL, "\t", &save);
            if (tok)
                ch->n_skipped = atoi(tok);
            tok = strtok_r(NULL, "\t", &save);
            if (tok && strcmp(tok, "-") && ch->n_skipped > 0) {
                int k = 0;
                for (sk_tok = strtok_r(tok, "|", &sk_save);
                     sk_tok && k < WA_SIG_MAX_SKIPPED && k < ch->n_skipped;
                     sk_tok = strtok_r(NULL, "|", &sk_save), k++) {
                    char *colon = strchr(sk_tok, ':');
                    if (!colon)
                        continue;
                    *colon = '\0';
                    ch->skipped[k].idx =
                        (uint32_t)strtoul(sk_tok, NULL, 10);
                    if (wa_b64_decode(colon + 1, ch->skipped[k].key, 32, &w) ||
                        w != 32)
                        ch->skipped[k].idx = 0;
                }
                ch->n_skipped = k;
            } else {
                ch->n_skipped = 0;
            }
            ss->n_chains++;
        }
    }
    free(line);
    fclose(f);
}

int wa_sig_load(wa_sig_t *s) {
    if (!s)
        return -1;
    load_prekeys(s);
    load_sessions(s);
    return 0;
}

int wa_sig_save(wa_sig_t *s) {
    if (!s)
        return -1;
    save_prekeys(s);
    save_sessions(s);
    return 0;
}

int wa_sig_has_session(const wa_sig_t *s, const char *addr) {
    for (int i = 0; i < s->n_sessions; i++)
        if (s->sessions[i].used && !strcmp(s->sessions[i].addr, addr))
            return 1;
    return 0;
}

/* ---------------- decrypt ---------------- */

int wa_sig_unpad(const uint8_t *in, size_t inlen, const uint8_t **out,
                 size_t *outlen) {
    size_t r;
    if (!in || !inlen)
        return -1;
    r = in[inlen - 1];
    if (r == 0 || r > inlen)
        return -1;
    *out = in;
    *outlen = inlen - r;
    return 0;
}

static int derive_msg_keys(const uint8_t mk[32], uint8_t enc[32], uint8_t mac[32],
                           uint8_t iv[16]) {
    uint8_t zeros[32] = { 0 }, k[96];
    if (derive((char *)k, 96, mk, 32, zeros, "WhisperMessageKeys"))
        return -1;
    memcpy(enc, k, 32);
    memcpy(mac, k + 32, 32);
    memcpy(iv, k + 64, 16);
    return 0;
}

/* Baileys writeRandomPadMax16: append 1..16 bytes equal to the pad length. */
static uint8_t *pad16(const uint8_t *in, size_t inlen, size_t *outlen) {
    uint8_t r;
    size_t padn;
    uint8_t *b;
    if (RAND_bytes(&r, 1) != 1)
        return NULL;
    padn = (size_t)((r & 0x0F) + 1);
    b = malloc(inlen + padn);
    if (!b)
        return NULL;
    memcpy(b, in, inlen);
    memset(b + inlen, (int)padn, padn);
    *outlen = inlen + padn;
    return b;
}

/* Decrypt one WhisperMessage payload (0x33 || protobuf || mac8). */
static int decrypt_whisper(wa_sig_t *s, wa_sig_session_t *ss, const uint8_t *buf,
                           size_t blen, uint8_t **out, size_t *outlen) {
    wa_pb_whisper_t wm;
    wa_sig_chain_t *ch;
    uint8_t mk[32], enc[32], mac[32], iv[16];
    uint8_t our33[33];
    uint8_t *mac_input = NULL;
    uint8_t *pt = NULL;
    int ptlen;
    int rc = -1;
    if (blen < 1 + 8 + 1 || buf[0] != 0x33)
        return -1;
    if (wa_pb_decode_whisper(buf + 1, blen - 1 - 8, &wm))
        return -1;
    if (wm.ephemeral_key_len != 33)
        return -1;
    if (maybe_step_ratchet(ss, wm.ephemeral_key, wm.previous_counter))
        return -1;
    ch = chain_by_peer(ss, wm.ephemeral_key);
    if (!ch || ch->is_sending)
        return -1;
    if (chain_message_key(ch, wm.counter, mk))
        return -1;
    if (derive_msg_keys(mk, enc, mac, iv))
        return -1;
    own_identity33(s, our33);
    mac_input = malloc(33 + 33 + 1 + (blen - 1 - 8));
    if (!mac_input)
        return -1;
    memcpy(mac_input, ss->remote_identity, 33);
    memcpy(mac_input + 33, our33, 33);
    mac_input[66] = 0x33;
    memcpy(mac_input + 67, buf + 1, blen - 1 - 8);
    {
        uint8_t full[32];
        if (wa_hmac_sha256(mac, 32, mac_input, 67 + (blen - 1 - 8), full))
            goto done;
        if (memcmp(full, buf + blen - 8, 8))
            goto done; /* bad MAC -> not our session / corrupt */
    }
    pt = malloc(wm.ciphertext_len + 16);
    if (!pt)
        goto done;
    ptlen = wa_aes_cbc_decrypt(wm.ciphertext, wm.ciphertext_len, enc, iv, pt,
                               wm.ciphertext_len + 16);
    if (ptlen < 0)
        goto done;
    {
        const uint8_t *up;
        size_t upl;
        if (wa_sig_unpad(pt, (size_t)ptlen, &up, &upl))
            goto done;
        memmove(pt, up, upl);
        *out = pt;
        *outlen = upl;
        pt = NULL;
        rc = 0;
    }
done:
    free(pt);
    free(mac_input);
    return rc;
}

static int init_responder_session(wa_sig_t *s, wa_sig_session_t *ss,
                                  const wa_pb_prekey_t *pk) {
    uint8_t shared[32 * 5], master[96];
    uint8_t a1[32], a2[32], a3[32], a4[32];
    uint8_t spk_priv[32];
    uint8_t spk_pub[32];
    uint8_t opk_priv[32];
    size_t shlen;
    memset(shared, 0xFF, 32);
    if (pk->signed_prekey_id != s->creds->pre_id) {
        /* still attempt with current signed prekey (single-key deployment) */
    }
    memcpy(spk_priv, s->creds->pre_priv, 32);
    memcpy(spk_pub, s->creds->pre_pub, 32);
    if (pk->identity_key_len != 33 || pk->base_key_len != 33)
        return -1;
    /* responder layout: 0xFF*32 || a2 || a1 || a3 [|| a4] */
    if (wa_x25519_shared(a1, s->creds->ident_priv, pk->base_key + 1))
        return -1;
    if (wa_x25519_shared(a2, spk_priv, pk->identity_key + 1))
        return -1;
    if (wa_x25519_shared(a3, spk_priv, pk->base_key + 1))
        return -1;
    memcpy(shared + 32, a2, 32);
    memcpy(shared + 64, a1, 32);
    memcpy(shared + 96, a3, 32);
    shlen = 128;
    if (pk->has_prekey_id) {
        if (opk_get(s, pk->prekey_id, opk_priv))
            return -1; /* unknown one-time prekey: cannot complete X3DH */
        if (wa_x25519_shared(a4, opk_priv, pk->base_key + 1))
            return -1;
        memcpy(shared + 128, a4, 32);
        shlen = 160;
    }
    {
        uint8_t zeros[32] = { 0 };
        if (derive((char *)master, 96, shared, shlen, zeros, "WhisperText"))
            return -1;
    }
    memset(ss, 0, sizeof(*ss));
    ss->used = 1;
    memcpy(ss->remote_identity, pk->identity_key, 33);
    memcpy(ss->root_key, master, 32);
    memcpy(ss->dhs_priv, spk_priv, 32);
    to33(ss->dhs_pub, spk_pub);
    ss->have_dhs = 1;
    memcpy(ss->dhr, pk->base_key, 33);
    ss->have_dhr = 1;
    memcpy(ss->base_key, pk->base_key, 33);
    ss->previous_counter = 0;
    return 0;
}

int wa_sig_decrypt(wa_sig_t *s, const char *addr, const char *type,
                   const uint8_t *body, size_t blen, uint8_t **out,
                   size_t *outlen) {
    wa_sig_session_t *ss;
    int rc;
    if (!s || !addr || !type || !body || !blen || !out || !outlen)
        return -1;
    ss = session_find(s, addr);
    if (!strcmp(type, "pkmsg")) {
        wa_pb_prekey_t pk;
        char addr_copy[WA_SIG_ADDR_MAX];
        uint8_t *inner = NULL;
        size_t innerlen = 0;
        int was_new = 0;
        if (blen < 2 || body[0] != 0x33)
            return -1;
        if (wa_pb_decode_prekey_msg(body + 1, blen - 1, &pk))
            return -1;
        if (!ss) {
            snprintf(addr_copy, sizeof(addr_copy), "%s", addr);
            ss = session_create(s, addr);
            if (!ss)
                return -1;
            if (init_responder_session(s, ss, &pk))
                return -1;
            snprintf(ss->addr, sizeof(ss->addr), "%s", addr_copy);
            was_new = 1;
        }
        inner = malloc(pk.message_len);
        if (!inner)
            return -1;
        memcpy(inner, pk.message, pk.message_len);
        innerlen = pk.message_len;
        rc = decrypt_whisper(s, ss, inner, innerlen, out, outlen);
        free(inner);
        if (!rc && was_new && pk.has_prekey_id) {
            opk_remove(s, pk.prekey_id);
            save_prekeys(s);
        }
        if (!rc)
            save_sessions(s);
        return rc;
    }
    if (!strcmp(type, "msg")) {
        if (!ss)
            return -1;
        rc = decrypt_whisper(s, ss, body, blen, out, outlen);
        if (!rc)
            save_sessions(s);
        return rc;
    }
    return -1;
}

/* ---------------- encrypt ---------------- */

static int build_whisper(wa_sig_t *s, wa_sig_session_t *ss, wa_sig_chain_t *ch,
                         const uint8_t *pt, size_t ptlen, uint8_t **out,
                         size_t *outlen) {
    uint32_t idx = ch->next_counter;
    uint8_t mk[32], enc[32], mac[32], iv[16];
    uint8_t our33[33];
    wa_pbw_t wm;
    uint8_t *proto = NULL;
    size_t protolen;
    uint8_t *ct = NULL;
    int ctlen;
    uint8_t *mac_input = NULL;
    uint8_t *buf = NULL;
    uint8_t *padded = NULL;
    size_t padded_len = 0;
    int rc = -1;
    if (chain_message_key(ch, idx, mk))
        return -1;
    if (derive_msg_keys(mk, enc, mac, iv))
        return -1;
    padded = pad16(pt, ptlen, &padded_len);
    if (!padded)
        return -1;
    ct = malloc(padded_len + 16);
    if (!ct) {
        free(padded);
        return -1;
    }
    ctlen = wa_aes_cbc_encrypt(padded, padded_len, enc, iv, ct, padded_len + 16);
    free(padded);
    if (ctlen < 0) {
        free(ct);
        return -1;
    }
    if (wa_pb_encode_whisper(ss->dhs_pub, idx, ss->previous_counter, ct,
                             (size_t)ctlen, &wm)) {
        free(ct);
        return -1;
    }
    free(ct);
    protolen = wm.len;
    proto = malloc(protolen);
    if (!proto) {
        wa_pbw_free(&wm);
        return -1;
    }
    memcpy(proto, wm.data, protolen);
    wa_pbw_free(&wm);
    own_identity33(s, our33);
    mac_input = malloc(33 + 33 + 1 + protolen);
    if (!mac_input)
        goto done;
    memcpy(mac_input, our33, 33);
    memcpy(mac_input + 33, ss->remote_identity, 33);
    mac_input[66] = 0x33;
    memcpy(mac_input + 67, proto, protolen);
    {
        uint8_t full[32];
        if (wa_hmac_sha256(mac, 32, mac_input, 67 + protolen, full))
            goto done;
        buf = malloc(1 + protolen + 8);
        if (!buf)
            goto done;
        buf[0] = 0x33;
        memcpy(buf + 1, proto, protolen);
        memcpy(buf + 1 + protolen, full, 8);
    }
    *out = buf;
    *outlen = 1 + protolen + 8;
    buf = NULL;
    rc = 0;
done:
    free(buf);
    free(mac_input);
    free(proto);
    return rc;
}

int wa_sig_encrypt(wa_sig_t *s, const char *addr, const uint8_t *pt,
                   size_t ptlen, uint8_t **out, size_t *outlen) {
    wa_sig_session_t *ss;
    wa_sig_chain_t *ch;
    if (!s || !addr || !pt || !out || !outlen)
        return -1;
    ss = session_find(s, addr);
    if (!ss || !ss->have_dhs)
        return -1;
    ch = chain_by_peer(ss, ss->dhs_pub);
    if (!ch || !ch->is_sending)
        return -1;
    if (build_whisper(s, ss, ch, pt, ptlen, out, outlen))
        return -1;
    save_sessions(s);
    return 0;
}

int wa_sig_encrypt_pkmsg(wa_sig_t *s, const char *addr, const wa_bundle_t *b,
                         const uint8_t *pt, size_t ptlen, uint8_t **out,
                         size_t *outlen) {
    uint8_t base_priv[32], base_pub[32], base33[33];
    uint8_t eph_priv[32], eph_pub[32], eph33[33];
    uint8_t our_id33[33], their_id33[33], spk33[33];
    uint8_t a1[32], a2[32], a3[32], a4[32];
    uint8_t *shared = NULL;
    size_t shared_len;
    uint8_t zeros[32];
    uint8_t master[96];
    uint8_t ss_shared[32], m2[64];
    uint8_t cur_root[32], chain_key[32], next_chain[32];
    wa_sig_session_t *sess;
    wa_sig_chain_t *ch;
    uint8_t *inner = NULL;
    size_t innerlen;
    uint8_t *body = NULL;
    int rc = -1;
    (void)s;

    memset(zeros, 0, 32);
    if (!s || !addr || !b || !pt || !out || !outlen)
        return -1;
    if (RAND_bytes(base_priv, 32) != 1 || RAND_bytes(eph_priv, 32) != 1)
        return -1;
    if (wa_x25519_pub(base_pub, base_priv) || wa_x25519_pub(eph_pub, eph_priv))
        return -1;
    to33(base33, base_pub);
    to33(eph33, eph_pub);
    own_identity33(s, our_id33);
    to33(their_id33, b->identity);
    to33(spk33, b->spk);

    if (wa_x25519_shared(a1, s->creds->ident_priv, b->spk) ||
        wa_x25519_shared(a2, base_priv, b->identity) ||
        wa_x25519_shared(a3, base_priv, b->spk))
        return -1;
    if (b->have_opk && wa_x25519_shared(a4, base_priv, b->opk))
        return -1;
    shared_len = b->have_opk ? 160 : 128;
    shared = malloc(shared_len);
    if (!shared)
        return -1;
    memset(shared, 0xFF, 32);
    memcpy(shared + 32, a1, 32); /* initiator layout a1,a2,a3[,a4] */
    memcpy(shared + 64, a2, 32);
    memcpy(shared + 96, a3, 32);
    if (b->have_opk)
        memcpy(shared + 128, a4, 32);
    if (derive((char *)master, 96, shared, shared_len, zeros, "WhisperText")) {
        free(shared);
        return -1;
    }
    free(shared);

    /* calculateSendingRatchet: DH(our eph, their spk) with rootKey=salt */
    if (wa_x25519_shared(ss_shared, eph_priv, b->spk) ||
        derive((char *)m2, 64, ss_shared, 32, master, "WhisperRatchet"))
        return -1;
    memcpy(cur_root, m2, 32);
    memcpy(chain_key, m2 + 32, 32);

    /* first message on the sending chain (index 0) */
    {
        static const uint8_t one = 1, two = 2;
        uint8_t mk[32], enc[32], mac[32], iv[16];
        uint8_t *ct = NULL;
        size_t padded_len = 0;
        int ctlen;
        wa_pbw_t wmsg;
        uint8_t *proto = NULL;
        size_t protolen;
        uint8_t *mac_input = NULL;
        if (wa_hmac_sha256(chain_key, 32, &one, 1, mk) ||
            wa_hmac_sha256(chain_key, 32, &two, 1, next_chain) ||
            derive_msg_keys(mk, enc, mac, iv))
            return -1;
        {
            uint8_t *padded = pad16(pt, ptlen, &padded_len);
            if (!padded)
                return -1;
            ct = malloc(padded_len + 16);
            if (!ct) {
                free(padded);
                return -1;
            }
            ctlen = wa_aes_cbc_encrypt(padded, padded_len, enc, iv, ct,
                                       padded_len + 16);
            free(padded);
        }
        if (ctlen < 0) {
            free(ct);
            return -1;
        }
        if (wa_pb_encode_whisper(eph33, 0, 0, ct, (size_t)ctlen, &wmsg)) {
            free(ct);
            return -1;
        }
        free(ct);
        protolen = wmsg.len;
        proto = malloc(protolen);
        if (!proto) {
            wa_pbw_free(&wmsg);
            return -1;
        }
        memcpy(proto, wmsg.data, protolen);
        wa_pbw_free(&wmsg);
        mac_input = malloc(33 + 33 + 1 + protolen);
        if (!mac_input) {
            free(proto);
            return -1;
        }
        memcpy(mac_input, our_id33, 33);
        memcpy(mac_input + 33, their_id33, 33);
        mac_input[66] = 0x33;
        memcpy(mac_input + 67, proto, protolen);
        {
            uint8_t full[32];
            if (wa_hmac_sha256(mac, 32, mac_input, 67 + protolen, full)) {
                free(mac_input);
                free(proto);
                return -1;
            }
            inner = malloc(1 + protolen + 8);
            if (!inner) {
                free(mac_input);
                free(proto);
                return -1;
            }
            inner[0] = 0x33;
            memcpy(inner + 1, proto, protolen);
            memcpy(inner + 1 + protolen, full, 8);
            innerlen = 1 + protolen + 8;
        }
        free(mac_input);
        free(proto);
    }

    {
        wa_pbw_t pre;
        if (wa_pb_encode_prekey_msg(our_id33, base33, s->creds->registration_id,
                                    b->spk_id, b->have_opk, b->opk_id, inner,
                                    innerlen, &pre)) {
            free(inner);
            return -1;
        }
        free(inner);
        body = malloc(1 + pre.len);
        if (!body) {
            wa_pbw_free(&pre);
            return -1;
        }
        body[0] = 0x33;
        memcpy(body + 1, pre.data, pre.len);
        *outlen = 1 + pre.len;
        *out = body;
        wa_pbw_free(&pre);
    }

    /* persist the initiator session so replies can be decrypted */
    sess = session_create(s, addr);
    if (sess) {
        sess->used = 1;
        snprintf(sess->addr, sizeof(sess->addr), "%s", addr);
        memcpy(sess->remote_identity, their_id33, 33);
        memcpy(sess->root_key, cur_root, 32);
        memcpy(sess->dhs_priv, eph_priv, 32);
        memcpy(sess->dhs_pub, eph33, 33);
        memcpy(sess->dhr, spk33, 33);
        sess->have_dhs = 1;
        sess->have_dhr = 1;
        sess->previous_counter = 0;
        memcpy(sess->base_key, base33, 33);
        ch = add_chain(sess, eph33, 1, next_chain);
        if (ch)
            ch->next_counter = 1;
        sess->pending_prekey = 0;
        save_sessions(s);
    }
    rc = 0;
    return rc;
}

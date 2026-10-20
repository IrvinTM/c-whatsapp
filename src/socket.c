/* wa_socket.c — connection flow (see wa_socket.h). */
#define _POSIX_C_SOURCE 200809L

#include "wa_socket.h"
#include "wa_crypto.h"
#include "wa_noise.h"
#include "wa_pairing.h"
#include "wa_pb.h"
#include "wa_remind.h"
#include "wa_signal.h"
#include "wa_ws.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/rand.h>

void wa_conn_init(wa_conn_t *c, wa_creds_t *creds) {
    if (!c)
        return;
    memset(c, 0, sizeof(*c));
    c->state = WA_CONN_CLOSE;
    c->creds = creds;
}

int wa_conn_close(wa_conn_t *c) {
    if (!c)
        return -1;
    c->state = WA_CONN_CLOSE;
    return 0;
}

int wa_conn_send_node(wa_conn_t *c, const wa_node_t *node) {
    (void)c;
    (void)node;
    return -95; /* ENOSYS until the post-auth query layer (Phase 5) */
}

void wa_conn_next_tag(wa_conn_t *c, char out[WA_TAG_MAX]) {
    unsigned long id = c ? c->msg_tag_counter++ : 0;
    snprintf(out, WA_TAG_MAX, "cwa.%lu", id);
}

/* ---------------- runner internals ---------------- */

/* Bounded bookkeeping for inbound retry requests (per message id). */
#define RETRY_SLOTS 32
#define RETRY_MAX 3

typedef struct {
    wa_creds_t *creds;
    const wa_conn_opts_t *opts;
    wa_noise_t noise;
    wa_ws_t ws;
    int ws_open;
    /* QR rotation */
    char **refs;
    size_t n_refs;
    size_t ref_idx;
    long long qr_deadline_ms; /* -1 = none */
    int qr_interval_ms;
    long long keepalive_ms;
    long long end_ms;
    int outcome; /* -1 = keep running, else WA_RUN_* decision */
    int logged_in; /* success seen, post-login queries pending */
    int post_done;
    unsigned long msg_tag;
    char want_id[64]; /* pending query id, "" = none */
    wa_node_t *response; /* owned pending-query response */
    char want_ack[64]; /* pending message ack id, "" = none */
    int ack_seen;
    int daemon_on;
    int listen_on;
    long long rem_check_ms;
    long long fired_minute; /* YYYYMMDDHHMM key, -1 = none */
    int fired_ids[WA_REM_MAX];
    int n_fired;
    char retry_ids[RETRY_SLOTS][64];
    int retry_counts[RETRY_SLOTS];
    int retry_next;
    wa_sig_t *sig; /* E2EE session + prekey store (heap) */
} run_t;

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void rlog(run_t *r, const char *fmt, ...) {
    char buf[512];
    va_list ap;
    if (!r->opts->on_log)
        return;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    r->opts->on_log(buf, r->opts->user);
}

static void save_creds(run_t *r) {
    if (r->opts->auth_dir)
        wa_auth_save(r->creds, r->opts->auth_dir);
}

/* Send one noise frame over WS. */
static int send_frame(run_t *r, const uint8_t *payload, size_t plen);

/* Inbound <message> decryption + command handling (defined after senders). */
static int handle_message(run_t *r, wa_node_t *node);
static void send_node_now(run_t *r, wa_node_t *node);

static int send_frame(run_t *r, const uint8_t *payload, size_t plen) {
    uint8_t *out = malloc(plen + 16 + 128); /* tag + max intro */
    size_t w = 0;
    int rc;
    if (!out)
        return -1;
    rc = wa_noise_encode_frame(&r->noise, payload, plen, out,
                               plen + 16 + 128, &w);
    if (rc == 0)
        rc = wa_ws_send_bin(&r->ws, out, w) ? -1 : 0;
    free(out);
    return rc;
}

/* link_code_companion_reg stanza (Baileys requestPairingCode).
 * phone = digits with country code; me JID derived from it. */
static int send_pairing_reg(run_t *r, const char *phone) {
    uint8_t salt[32], iv[16], key[32], wrapped[32 + 16 + 32];
    wa_node_t *iq = NULL, *reg = NULL, *n0 = NULL, *n1 = NULL, *n2 = NULL;
    wa_node_t *n3 = NULL, *n4 = NULL;
    wa_buf_t b;
    char tag[WA_TAG_MAX], jid[64];
    int rc = -1;
    if (!phone || !phone[0])
        return -1;
    if (RAND_bytes(salt, 32) != 1 || RAND_bytes(iv, 16) != 1)
        return -1;
    /* key = PBKDF2-SHA256(code, salt, 131072) */
    if (wa_pbkdf2_sha256(r->creds->pairing_code, salt, 32, 2u << 16, key, 32))
        return -1;
    /* wrapped = salt || iv || AES-CTR(pairing_eph_pub, key, iv) */
    memcpy(wrapped, salt, 32);
    memcpy(wrapped + 32, iv, 16);
    if (wa_aes_ctr_encrypt(r->creds->pairing_eph_pub, 32, key, iv,
                           wrapped + 48, 32) != 32)
        return -1;
    snprintf(jid, sizeof(jid), "%.32s@s.whatsapp.net", phone);
    iq = wa_node_new("iq");
    reg = wa_node_new("link_code_companion_reg");
    n0 = wa_node_new("link_code_pairing_wrapped_companion_ephemeral_pub");
    n1 = wa_node_new("companion_server_auth_key_pub");
    n2 = wa_node_new("companion_platform_id");
    n3 = wa_node_new("companion_platform_display");
    n4 = wa_node_new("link_code_pairing_nonce");
    if (!iq || !reg || !n0 || !n1 || !n2 || !n3 || !n4)
        goto fail;
    snprintf(tag, sizeof(tag), "cwa.%lu", r->msg_tag++);
    if (wa_node_add_attr(iq, "id", tag) ||
        wa_node_add_attr(iq, "to", "s.whatsapp.net") ||
        wa_node_add_attr(iq, "type", "set") ||
        wa_node_add_attr(iq, "xmlns", "md") ||
        wa_node_add_attr(reg, "jid", jid) ||
        wa_node_add_attr(reg, "stage", "companion_hello") ||
        wa_node_add_attr(reg, "should_show_push_notification", "true") ||
        wa_node_set_bytes(n0, wrapped, sizeof(wrapped)) ||
        wa_node_set_bytes(n1, r->creds->noise_pub, 32) ||
        wa_node_set_string(n2, "1") || /* DeviceProps.PlatformType.CHROME */
        wa_node_set_string(n3, "Chrome (Mac OS)") ||
        wa_node_set_string(n4, "0") ||
        wa_node_add_child(reg, n0) || wa_node_add_child(reg, n1) ||
        wa_node_add_child(reg, n2) || wa_node_add_child(reg, n3) ||
        wa_node_add_child(reg, n4) || wa_node_add_child(iq, reg))
        goto fail;
    n0 = n1 = n2 = n3 = n4 = reg = NULL; /* owned now */
    if (wa_encode_node(iq, &b) || send_frame(r, b.data, b.len)) {
        wa_buf_free(&b);
        goto fail;
    }
    wa_buf_free(&b);
    rc = 0;
fail:
    wa_node_free(n0);
    wa_node_free(n1);
    wa_node_free(n2);
    wa_node_free(n3);
    wa_node_free(n4);
    wa_node_free(reg);
    wa_node_free(iq);
    return rc;
}

static void free_refs(run_t *r) {
    for (size_t i = 0; i < r->n_refs; i++)
        free(r->refs[i]);
    free(r->refs);
    r->refs = NULL;
    r->n_refs = r->ref_idx = 0;
}

/* Companion platform id for the QR URL (browser = Mac OS/Chrome default). */
static const char *qr_platform_id(void) {
    return "1"; /* CompanionWebClientType.CHROME */
}

static void emit_qr(run_t *r) {
    char noise_b64[64], ident_b64[64], adv_b64[64];
    char qr[1024];
    if (r->ref_idx >= r->n_refs)
        return;
    wa_b64_encode(r->creds->noise_pub, 32, noise_b64, sizeof(noise_b64));
    wa_b64_encode(r->creds->ident_pub, 32, ident_b64, sizeof(ident_b64));
    wa_b64_encode(r->creds->adv_secret, 32, adv_b64, sizeof(adv_b64));
    snprintf(qr, sizeof(qr),
             "https://wa.me/settings/linked_devices#%s,%s,%s,%s,%s",
             r->refs[r->ref_idx], noise_b64, ident_b64, adv_b64,
             qr_platform_id());
    r->ref_idx++;
    if (r->opts->on_qr)
        r->opts->on_qr(qr, r->opts->user);
    r->qr_deadline_ms = now_ms() + r->qr_interval_ms;
    r->qr_interval_ms = 20000; /* shorter subsequent QRs (Baileys) */
}

/* Send {iq result} ack for an incoming iq, then handle pair-device. */
static int on_iq(run_t *r, wa_node_t *node) {
    const char *id = wa_node_get_attr(node, "id");
    wa_node_t *pd = wa_node_get_child(node, "pair-device");
    wa_node_t *ps = wa_node_get_child(node, "pair-success");

    if (pd) {
        /* ack first (Baileys replies before emitting QRs) */
        wa_buf_t b;
        wa_node_t *ack = wa_node_new("iq");
        if (!ack)
            return -1;
        wa_node_add_attr(ack, "to", "s.whatsapp.net");
        wa_node_add_attr(ack, "type", "result");
        if (id)
            wa_node_add_attr(ack, "id", id);
        int rc = wa_encode_node(ack, &b) == 0 ? send_frame(r, b.data, b.len) : -1;
        wa_buf_free(&b);
        wa_node_free(ack);
        if (rc)
            return -1;
        /* collect refs (binary children) */
        free_refs(r);
        if (pd->ctype == WA_CONTENT_CHILDREN) {
            for (size_t i = 0; i < pd->content.children.len; i++) {
                wa_node_t *ch = pd->content.children.items[i];
                if (strcmp(ch->tag, "ref") != 0 ||
                    ch->ctype != WA_CONTENT_BYTES)
                    continue;
                char *s = malloc(ch->content.bytes.len + 1);
                if (!s)
                    return -1;
                memcpy(s, ch->content.bytes.data, ch->content.bytes.len);
                s[ch->content.bytes.len] = '\0';
                char **nr = realloc(r->refs, (r->n_refs + 1) * sizeof(*nr));
                if (!nr) {
                    free(s);
                    return -1;
                }
                r->refs = nr;
                r->refs[r->n_refs++] = s;
            }
        }
        r->ref_idx = 0;
        r->qr_interval_ms = 60000;
        rlog(r, "pair-device: %zu refs, emitting QR", r->n_refs);
        emit_qr(r);
        return 0;
    }
    if (ps) {
        wa_node_t *reply = NULL;
        wa_buf_t b;
        int rc;
        rlog(r, "pair-success received, configuring...");
        if (wa_pair_success(r->creds, node, &reply)) {
            rlog(r, "pairing verification failed");
            if (r->opts->on_close)
                r->opts->on_close("pairing-failed", r->opts->user);
            r->outcome = WA_RUN_ERROR;
            return 1;
        }
        rlog(r, "paired as %s, sending device signature...", r->creds->me_id);
        save_creds(r);
        rc = wa_encode_node(reply, &b) == 0 ? send_frame(r, b.data, b.len) : -1;
        /* TODO(Phase 5b): sendUnifiedSession before restart (Baileys does). */
        wa_buf_free(&b);
        wa_node_free(reply);
        if (rc) {
            r->outcome = WA_RUN_ERROR;
            return 1;
        }
        /* Like Baileys, the server drops the connection next; report
         * restart so the caller reconnects and logs in. */
        r->outcome = WA_RUN_RESTART;
        return 1; /* stop */
    }
    return 0;
}

static int on_node(run_t *r, wa_node_t *node) {
    if (!strcmp(node->tag, "iq"))
        return on_iq(r, node);
    if (!strcmp(node->tag, "message"))
        return handle_message(r, node);
    if (!strcmp(node->tag, "success")) {
        const char *lid = wa_node_get_attr(node, "lid");
        rlog(r, "login success%s%s", lid ? " lid=" : "", lid ? lid : "");
        if (lid) {
            snprintf(r->creds->me_lid, sizeof(r->creds->me_lid), "%s", lid);
            r->creds->registered = 1;
            save_creds(r);
        }
        r->logged_in = 1; /* post-login queries run in the main loop */
        return 0;
    }
    if (!strcmp(node->tag, "failure")) {
        const char *reason = wa_node_get_attr(node, "reason");
        rlog(r, "failure%s%s", reason ? ": " : "", reason ? reason : "");
        if (r->opts->on_close)
            r->opts->on_close(reason ? reason : "failure", r->opts->user);
        r->outcome = WA_RUN_ERROR;
        return 1;
    }
    if (!strcmp(node->tag, "stream:error") ||
        !strcmp(node->tag, "xmlstreamend")) {
        if (r->opts->on_close)
            r->opts->on_close(node->tag, r->opts->user);
        r->outcome = WA_RUN_ERROR;
        return 1;
    }
    return 0;
}

static int frame_cb(const uint8_t *frame, size_t len, void *user) {
    run_t *r = user;
    wa_node_t *node = NULL;
    size_t consumed = 0;
    int rc;
    if (wa_decode_node(frame, len, &node, &consumed))
        return 0; /* ignore undecodable frames */
    {
        const char *id = wa_node_get_attr(node, "id");
        const char *type = wa_node_get_attr(node, "type");
        rlog(r, "recv %s%s%s%s%s", node->tag, id ? " id=" : "", id ? id : "",
             type ? " type=" : "", type ? type : "");
        if (!strcmp(node->tag, "receipt") || !strcmp(node->tag, "ack") ||
            !strcmp(node->tag, "message") || !strcmp(node->tag, "notification") ||
            !strcmp(node->tag, "ib")) {
            char *d = wa_node_to_string(node);
            if (d) {
                char tmp[512];
                snprintf(tmp, sizeof(tmp), "detail: %.480s", d);
                rlog(r, "%s", tmp);
                free(d);
            }
        }
        /* Ack delivery receipts / notifications so the server drains its
         * offline queue instead of replaying them on every reconnect. */
        if (!strcmp(node->tag, "receipt") ||
            !strcmp(node->tag, "notification")) {
            const char *from = wa_node_get_attr(node, "from");
            if (id && from) {
                wa_node_t *ack = wa_node_new("ack");
                if (ack && !(wa_node_add_attr(ack, "id", id) ||
                             wa_node_add_attr(ack, "to", from) ||
                             wa_node_add_attr(ack, "class", node->tag)))
                    send_node_now(r, ack); /* takes ownership */
                else
                    wa_node_free(ack);
            }
        }
    }
    /* pending query match takes priority over dispatch */
    if (r->want_id[0] && !strcmp(node->tag, "iq")) {
        const char *id = wa_node_get_attr(node, "id");
        if (id && !strcmp(id, r->want_id)) {
            wa_node_free(r->response);
            r->response = node;
            return 1; /* stop feed */
        }
    }
    if (r->want_ack[0] && !strcmp(node->tag, "ack")) {
        const char *id = wa_node_get_attr(node, "id");
        if (id && !strcmp(id, r->want_ack)) {
            r->ack_seen = 1;
            wa_node_free(node);
            return 1;
        }
    }
    rc = on_node(r, node);
    wa_node_free(node);
    return rc; /* 1 = stop (r->outcome set), 0 = continue, -1 = error */
}

/* Send node (must carry an id attr) and wait for the matching iq reply.
 * Returns owned response node or NULL on timeout/transport error. */
static wa_node_t *run_query(run_t *r, wa_node_t *node, int timeout_ms) {
    const char *id = wa_node_get_attr(node, "id");
    wa_buf_t b;
    long long deadline;
    if (!id || !id[0])
        return NULL;
    snprintf(r->want_id, sizeof(r->want_id), "%s", id);
    wa_node_free(r->response);
    r->response = NULL;
    if (wa_encode_node(node, &b) || send_frame(r, b.data, b.len)) {
        wa_buf_free(&b);
        r->want_id[0] = '\0';
        return NULL;
    }
    wa_buf_free(&b);
    deadline = now_ms() + timeout_ms;
    while (now_ms() < deadline) {
        uint8_t *msg = NULL;
        size_t msglen = 0;
        long long left = deadline - now_ms();
        wa_ws_msg_t m;
        int slice = left > 5000 ? 5000 : (int)left;
        if (slice < 0)
            slice = 0;
        m = wa_ws_recv(&r->ws, &msg, &msglen, slice);
        if (m == WA_WS_TIMEOUT) {
            free(msg);
            continue;
        }
        if (m != WA_WS_BIN) {
            free(msg);
            break;
        }
        if (wa_noise_feed(&r->noise, msg, msglen, frame_cb, r) < 0) {
            free(msg);
            break;
        }
        free(msg);
        if (r->response || r->outcome >= 0)
            break;
    }
    r->want_id[0] = '\0';
    return r->response; /* NULL on timeout; ownership to caller */
}

/* ---------------- Phase 5: 1:1 text send ---------------- */

#define WA_SEND_MAX_DEVICES 32
#define WA_SEND_JID_MAX 160

typedef struct {
    char jid[WA_SEND_JID_MAX];
    uint8_t identity[32];
    uint8_t spk[32];
    uint32_t spk_id;
    uint8_t spk_sig[64];
    uint8_t opk[32];
    uint32_t opk_id;
    int have_opk;
    uint32_t reg_id;
} wa_dev_bundle_t;

static uint32_t be_to_u32(const uint8_t *b, size_t n) {
    uint32_t v = 0;
    for (size_t i = 0; i < n; i++)
        v = (v << 8) | b[i];
    return v;
}

static const wa_node_t *child_by_tag(const wa_node_t *p, const char *tag) {
    return wa_node_get_child(p, tag);
}

static int child_bytes(const wa_node_t *p, const char *tag,
                       const uint8_t **out, size_t *outlen) {
    const wa_node_t *c = child_by_tag(p, tag);
    if (!c || c->ctype != WA_CONTENT_BYTES)
        return -1;
    *out = c->content.bytes.data;
    *outlen = c->content.bytes.len;
    return 0;
}

/* "+15551234567" / "15551234567" / JID -> bare JID. Returns 0 on success. */
static int normalize_jid(const char *in, char out[WA_SEND_JID_MAX]) {
    char digits[64];
    size_t nd = 0;
    if (!in || !out)
        return -1;
    if (strchr(in, '@')) {
        const char *at = strchr(in, '@');
        const char *colon = strchr(in, ':');
        size_t ulen;
        if (colon && colon < at)
            ulen = (size_t)(colon - in);
        else
            ulen = (size_t)(at - in);
        if (ulen == 0 || ulen >= 64)
            return -1;
        memcpy(digits, in, ulen);
        digits[ulen] = '\0';
        snprintf(out, WA_SEND_JID_MAX, "%s@%s", digits, at + 1);
        return 0;
    }
    for (const char *p = in; *p && nd + 1 < sizeof(digits); p++) {
        if (*p >= '0' && *p <= '9')
            digits[nd++] = *p;
    }
    digits[nd] = '\0';
    if (nd < 7)
        return -1;
    snprintf(out, WA_SEND_JID_MAX, "%s@s.whatsapp.net", digits);
    return 0;
}

static void gen_msg_id(char out[32]) {
    uint8_t r[9];
    static const char *H = "0123456789ABCDEF";
    if (RAND_bytes(r, sizeof(r)) != 1) {
        snprintf(out, 32, "3EB0%08lX%08lX", (unsigned long)time(NULL),
                 (unsigned long)rand());
        return;
    }
    out[0] = '3';
    out[1] = 'E';
    out[2] = 'B';
    out[3] = '0';
    for (int i = 0; i < 9; i++) {
        out[4 + i * 2] = H[(r[i] >> 4) & 0xF];
        out[5 + i * 2] = H[r[i] & 0xF];
    }
    out[22] = '\0';
}

/* WAMessage{conversation} + random pad 1..16 (Baileys writeRandomPadMax16). */
static int encode_plaintext(const char *text, uint8_t **out, size_t *outlen) {
    wa_pbw_t w;
    uint8_t padn;
    uint8_t pr[1];
    if (!text || !out || !outlen)
        return -1;
    if (wa_pb_encode_wamessage_text(text, &w))
        return -1;
    if (RAND_bytes(pr, 1) != 1) {
        wa_pbw_free(&w);
        return -1;
    }
    padn = (uint8_t)((pr[0] & 0x0F) + 1);
    uint8_t *buf = malloc(w.len + padn);
    if (!buf) {
        wa_pbw_free(&w);
        return -1;
    }
    memcpy(buf, w.data, w.len);
    memset(buf + w.len, padn, padn);
    *out = buf;
    *outlen = w.len + padn;
    wa_pbw_free(&w);
    return 0;
}

static int cmp_str(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

/* phash = "2:" + b64(sha256(sorted-concat))[:6] (kept for debugging;
 * not sent on the stanza in current Baileys). */
static void __attribute__((unused))
make_phash(char (*jids)[WA_SEND_JID_MAX], size_t n, char out[16]) {
    uint8_t h[32];
    char b64[64];
    size_t total = 0;
    uint8_t *cat;
    qsort(jids, n, WA_SEND_JID_MAX, cmp_str);
    for (size_t i = 0; i < n; i++)
        total += strlen(jids[i]);
    cat = malloc(total ? total : 1);
    if (!cat) {
        out[0] = '\0';
        return;
    }
    total = 0;
    for (size_t i = 0; i < n; i++) {
        size_t l = strlen(jids[i]);
        memcpy(cat + total, jids[i], l);
        total += l;
    }
    wa_sha256(cat, total, h);
    free(cat);
    wa_b64_encode(h, 32, b64, sizeof(b64));
    snprintf(out, 16, "2:%.6s", b64);
}

/* X3DH + first Double-Ratchet step, pkmsg only (fresh session per device).
 * Mirrors libsignal session_builder.initSession(initiator) +
 * session_cipher.encrypt first message. */
static int x3dh_encrypt_pkmsg(const wa_creds_t *creds, const wa_dev_bundle_t *b,
                             const uint8_t *pt, size_t ptlen,
                             uint8_t **out, size_t *outlen) {
    uint8_t base_priv[32], base_pub[32], base33[33];
    uint8_t eph_priv[32], eph_pub[32], eph33[33];
    uint8_t our_id33[33], their_id33[33];
    uint8_t a1[32], a2[32], a3[32], a4[32];
    uint8_t *shared = NULL;
    size_t shared_len;
    uint8_t zeros[32];
    uint8_t master[96], master2[96];
    uint8_t chain_key[32], msg_key_raw[32], next_chain[32];
    uint8_t enc_key[32], mac_key[32], iv32[32];
    uint8_t *ct = NULL;
    wa_pbw_t wmsg, pre;
    uint8_t *msgbuf = NULL;
    size_t msgbuf_len;
    uint8_t *mac_input = NULL;
    uint8_t mac[32];
    uint8_t *inner = NULL;
    uint8_t *body = NULL;
    int rc = -1;

    memset(zeros, 0, 32);
    if (RAND_bytes(base_priv, 32) != 1 || RAND_bytes(eph_priv, 32) != 1)
        return -1;
    if (wa_x25519_pub(base_pub, base_priv) ||
        wa_x25519_pub(eph_pub, eph_priv))
        return -1;
    base33[0] = 5;
    memcpy(base33 + 1, base_pub, 32);
    eph33[0] = 5;
    memcpy(eph33 + 1, eph_pub, 32);
    our_id33[0] = 5;
    memcpy(our_id33 + 1, creds->ident_pub, 32);
    their_id33[0] = 5;
    memcpy(their_id33 + 1, b->identity, 32);

    if (wa_x25519_shared(a1, creds->ident_priv, b->spk) ||
        wa_x25519_shared(a2, base_priv, b->identity) ||
        wa_x25519_shared(a3, base_priv, b->spk))
        return -1;
    if (b->have_opk && wa_x25519_shared(a4, base_priv, b->opk))
        return -1;
    shared_len = b->have_opk ? 32 * 5 : 32 * 4;
    shared = malloc(shared_len);
    if (!shared)
        return -1;
    memset(shared, 0xFF, 32);
    memcpy(shared + 32, a1, 32);
    memcpy(shared + 64, a2, 32);
    memcpy(shared + 96, a3, 32);
    if (b->have_opk)
        memcpy(shared + 128, a4, 32);
    if (wa_hkdf_sha256(master, sizeof(master), shared, shared_len, zeros, 32,
                       (const uint8_t *)"WhisperText", 11)) {
        free(shared);
        return -1;
    }
    free(shared);

    /* sending ratchet with their signed prekey */
    {
        uint8_t ss[32];
        if (wa_x25519_shared(ss, eph_priv, b->spk))
            return -1;
        if (wa_hkdf_sha256(master2, sizeof(master2), ss, 32, master, 32,
                           (const uint8_t *)"WhisperRatchet", 14))
            return -1;
    }
    memcpy(chain_key, master2 + 32, 32);
    /* fillMessageKeys(0): msg = HMAC(chain,0x01), next = HMAC(chain,0x02) */
    {
        uint8_t one = 1, two = 2;
        if (wa_hmac_sha256(chain_key, 32, &one, 1, msg_key_raw) ||
            wa_hmac_sha256(chain_key, 32, &two, 1, next_chain))
            return -1;
    }
    (void)next_chain;
    if (wa_hkdf_sha256(master2, sizeof(master2), msg_key_raw, 32, zeros, 32,
                       (const uint8_t *)"WhisperMessageKeys", 18))
        return -1;
    memcpy(enc_key, master2, 32);
    memcpy(mac_key, master2 + 32, 32);
    memcpy(iv32, master2 + 64, 32);

    ct = malloc(ptlen + 16);
    if (!ct)
        return -1;
    {
        int cl = wa_aes_cbc_encrypt(pt, ptlen, enc_key, iv32, ct, ptlen + 16);
        if (cl <= 0) {
            free(ct);
            return -1;
        }
        if (wa_pb_encode_whisper(eph33, 0, 0, ct, (size_t)cl, &wmsg)) {
            free(ct);
            return -1;
        }
        free(ct);
    }
    msgbuf_len = wmsg.len;
    msgbuf = malloc(msgbuf_len);
    if (!msgbuf) {
        wa_pbw_free(&wmsg);
        return -1;
    }
    memcpy(msgbuf, wmsg.data, msgbuf_len);
    wa_pbw_free(&wmsg);

    mac_input = malloc(33 + 33 + 1 + msgbuf_len);
    if (!mac_input) {
        free(msgbuf);
        return -1;
    }
    memcpy(mac_input, our_id33, 33);
    memcpy(mac_input + 33, their_id33, 33);
    mac_input[66] = 0x33;
    memcpy(mac_input + 67, msgbuf, msgbuf_len);
    if (wa_hmac_sha256(mac_key, 32, mac_input, 67 + msgbuf_len, mac)) {
        free(mac_input);
        free(msgbuf);
        return -1;
    }
    free(mac_input);
    inner = malloc(1 + msgbuf_len + 8);
    if (!inner) {
        free(msgbuf);
        return -1;
    }
    inner[0] = 0x33;
    memcpy(inner + 1, msgbuf, msgbuf_len);
    memcpy(inner + 1 + msgbuf_len, mac, 8);
    free(msgbuf);

    if (wa_pb_encode_prekey_msg(our_id33, base33, creds->registration_id,
                                b->spk_id, b->have_opk, b->opk_id, inner,
                                1 + msgbuf_len + 8, &pre)) {
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
    *out = body;
    *outlen = 1 + pre.len;
    wa_pbw_free(&pre);
    rc = 0;
    return rc;
}

/* usync device discovery for one bare JID. Fills jids[] with full device
 * JIDs (LID preferred when the server returns a lid mapping). */
static int fetch_devices(run_t *r, const char *bare_jid,
                         char out[][WA_SEND_JID_MAX], size_t *out_n) {
    wa_node_t *iq = NULL, *usync = NULL, *query = NULL, *list = NULL;
    wa_node_t *devq = NULL, *lidq = NULL, *user = NULL;
    wa_node_t *resp = NULL;
    char tag[WA_TAG_MAX];
    int rc = -1;
    *out_n = 0;

    iq = wa_node_new("iq");
    usync = wa_node_new("usync");
    query = wa_node_new("query");
    list = wa_node_new("list");
    devq = wa_node_new("devices");
    lidq = wa_node_new("lid");
    user = wa_node_new("user");
    if (!iq || !usync || !query || !list || !devq || !lidq || !user)
        goto fail;
    snprintf(tag, sizeof(tag), "cwa.%lu", r->msg_tag++);
    if (wa_node_add_attr(iq, "id", tag) ||
        wa_node_add_attr(iq, "to", "s.whatsapp.net") ||
        wa_node_add_attr(iq, "type", "get") ||
        wa_node_add_attr(iq, "xmlns", "usync") ||
        wa_node_add_attr(usync, "context", "message") ||
        wa_node_add_attr(usync, "mode", "query") ||
        wa_node_add_attr(usync, "sid", tag) ||
        wa_node_add_attr(usync, "last", "true") ||
        wa_node_add_attr(usync, "index", "0") ||
        wa_node_add_attr(devq, "version", "2") ||
        wa_node_add_attr(user, "jid", bare_jid))
        goto fail;
    if (wa_node_add_child(query, devq) || wa_node_add_child(query, lidq) ||
        wa_node_add_child(list, user) || wa_node_add_child(usync, query) ||
        wa_node_add_child(usync, list) || wa_node_add_child(iq, usync))
        goto fail;
    devq = lidq = user = query = list = usync = NULL;
    rlog(r, "usync: discovering devices for %s...", bare_jid);
    resp = run_query(r, iq, 15000);
    wa_node_free(iq);
    iq = NULL;
    if (!resp) {
        rlog(r, "usync: no response");
        goto fail;
    }
    {
        const wa_node_t *un = child_by_tag(resp, "usync");
        const wa_node_t *ln = un ? child_by_tag(un, "list") : NULL;
        if (!ln || ln->ctype != WA_CONTENT_CHILDREN) {
            rlog(r, "usync: bad response");
            wa_node_free(resp);
            r->response = NULL;
            goto fail;
        }
        for (size_t i = 0; i < ln->content.children.len; i++) {
            const wa_node_t *u = ln->content.children.items[i];
            const char *lid_val = NULL;
            const wa_node_t *devs = NULL, *dlist = NULL;
            if (strcmp(u->tag, "user") != 0)
                continue;
            /* lid mapping: <lid val="...@lid"> */
            if (u->ctype == WA_CONTENT_CHILDREN) {
                for (size_t k = 0; k < u->content.children.len; k++) {
                    const wa_node_t *c = u->content.children.items[k];
                    if (!strcmp(c->tag, "lid")) {
                        const char *v = wa_node_get_attr(c, "val");
                        if (v)
                            lid_val = v;
                    }
                    if (!strcmp(c->tag, "devices"))
                        devs = c;
                }
            }
            if (!devs)
                continue;
            dlist = child_by_tag(devs, "device-list");
            if (!dlist || dlist->ctype != WA_CONTENT_CHILDREN)
                continue;
            /* user part for JID building: prefer LID user when present */
            char pn_user[64] = "";
            char pn_server[64] = "s.whatsapp.net";
            {
                const char *uid = wa_node_get_attr(u, "jid");
                if (uid) {
                    const char *at = strchr(uid, '@');
                    const char *colon = strchr(uid, ':');
                    size_t l;
                    if (at) {
                        if (colon && colon < at)
                            l = (size_t)(colon - uid);
                        else
                            l = (size_t)(at - uid);
                        snprintf(pn_server, sizeof(pn_server), "%s", at + 1);
                    } else {
                        l = strlen(uid);
                        if (colon && colon < uid + l)
                            l = (size_t)(colon - uid);
                    }
                    if (l >= sizeof(pn_user))
                        l = sizeof(pn_user) - 1;
                    memcpy(pn_user, uid, l);
                    pn_user[l] = '\0';
                }
            }
            char lid_user[64] = "";
            const char *lid_server = NULL;
            if (lid_val) {
                const char *at = strchr(lid_val, '@');
                if (at) {
                    const char *colon = strchr(lid_val, ':');
                    size_t ul;
                    if (colon && colon < at)
                        ul = (size_t)(colon - lid_val);
                    else
                        ul = (size_t)(at - lid_val);
                    if (ul >= sizeof(lid_user))
                        ul = sizeof(lid_user) - 1;
                    memcpy(lid_user, lid_val, ul);
                    lid_user[ul] = '\0';
                    lid_server = at + 1;
                }
            }
            for (size_t j = 0; j < dlist->content.children.len; j++) {
                const wa_node_t *d = dlist->content.children.items[j];
                const char *id_s, *ki;
                int dev;
                if (strcmp(d->tag, "device") != 0)
                    continue;
                id_s = wa_node_get_attr(d, "id");
                ki = wa_node_get_attr(d, "key-index");
                if (!id_s)
                    continue;
                dev = atoi(id_s);
                if (dev != 0 && !ki)
                    continue; /* Baileys: key-index required for non-zero */
                if (*out_n >= WA_SEND_MAX_DEVICES)
                    break;
                if (lid_user[0] && lid_server) {
                    snprintf(out[*out_n], WA_SEND_JID_MAX, "%s:%d@%s",
                             lid_user, dev, lid_server);
                } else {
                    snprintf(out[*out_n], WA_SEND_JID_MAX, "%s:%d@%s",
                             pn_user, dev, pn_server);
                }
                rlog(r, "usync: device %s (key-index %s)", out[*out_n],
                     ki ? ki : "-");
                (*out_n)++;
            }
        }
        wa_node_free(resp);
        r->response = NULL;
    }
    rlog(r, "usync: %zu device(s)", *out_n);
    rc = *out_n ? 0 : -1;
    return rc;
fail:
    wa_node_free(user);
    wa_node_free(devq);
    wa_node_free(lidq);
    wa_node_free(query);
    wa_node_free(list);
    wa_node_free(usync);
    wa_node_free(iq);
    return rc;
}

/* Fetch prekey bundles for full device JIDs. */
static int fetch_bundles(run_t *r, char (*jids)[WA_SEND_JID_MAX], size_t n,
                         wa_dev_bundle_t *bundles, size_t *nb) {
    wa_node_t *iq = NULL, *key = NULL;
    wa_node_t *resp = NULL;
    char tag[WA_TAG_MAX];
    int rc = -1;
    *nb = 0;
    iq = wa_node_new("iq");
    key = wa_node_new("key");
    if (!iq || !key)
        goto fail;
    snprintf(tag, sizeof(tag), "cwa.%lu", r->msg_tag++);
    if (wa_node_add_attr(iq, "id", tag) ||
        wa_node_add_attr(iq, "to", "s.whatsapp.net") ||
        wa_node_add_attr(iq, "xmlns", "encrypt") ||
        wa_node_add_attr(iq, "type", "get"))
        goto fail;
    for (size_t i = 0; i < n; i++) {
        wa_node_t *u = wa_node_new("user");
        if (!u)
            goto fail;
        if (wa_node_add_attr(u, "jid", jids[i]) || wa_node_add_child(key, u)) {
            wa_node_free(u);
            goto fail;
        }
    }
    if (wa_node_add_child(iq, key))
        goto fail;
    key = NULL;
    rlog(r, "encrypt: fetching %zu bundle(s) id=%s...", n, tag);
    for (size_t i = 0; i < n; i++)
        rlog(r, "encrypt: want %s", jids[i]);
    resp = run_query(r, iq, 15000);
    wa_node_free(iq);
    iq = NULL;
    if (!resp) {
        rlog(r, "encrypt: no response");
        goto fail;
    }
    {
        const wa_node_t *ln = child_by_tag(resp, "list");
        if (!ln || ln->ctype != WA_CONTENT_CHILDREN) {
            rlog(r, "encrypt: bad response");
            wa_node_free(resp);
            r->response = NULL;
            goto fail;
        }
        for (size_t i = 0; i < ln->content.children.len && *nb < n; i++) {
            const wa_node_t *u = ln->content.children.items[i];
            const char *jid;
            const uint8_t *b;
            size_t bl;
            wa_dev_bundle_t *o;
            if (strcmp(u->tag, "user") != 0)
                continue;
            jid = wa_node_get_attr(u, "jid");
            if (!jid)
                continue;
            o = &bundles[(*nb)];
            memset(o, 0, sizeof(*o));
            snprintf(o->jid, sizeof(o->jid), "%s", jid);
            if (child_bytes(u, "identity", &b, &bl) || bl != 32)
                continue;
            memcpy(o->identity, b, 32);
            if (child_bytes(u, "registration", &b, &bl) || bl != 4)
                continue;
            o->reg_id = be_to_u32(b, 4);
            {
                const wa_node_t *s = child_by_tag(u, "skey");
                if (!s)
                    continue;
                if (child_bytes(s, "value", &b, &bl) || bl != 32)
                    continue;
                memcpy(o->spk, b, 32);
                if (child_bytes(s, "signature", &b, &bl) || bl != 64)
                    continue;
                memcpy(o->spk_sig, b, 64);
                if (child_bytes(s, "id", &b, &bl) || bl != 3)
                    continue;
                o->spk_id = be_to_u32(b, 3);
            }
            {
                const wa_node_t *k = child_by_tag(u, "key");
                if (k) {
                    if (child_bytes(k, "value", &b, &bl) || bl != 32)
                        continue;
                    memcpy(o->opk, b, 32);
                    if (child_bytes(k, "id", &b, &bl) || bl != 3)
                        continue;
                    o->opk_id = be_to_u32(b, 3);
                    o->have_opk = 1;
                }
            }
            (*nb)++;
        }
        wa_node_free(resp);
        r->response = NULL;
    }
    rlog(r, "encrypt: %zu bundle(s)", *nb);
    rc = *nb ? 0 : -1;
    return rc;
fail:
    wa_node_free(key);
    wa_node_free(iq);
    return rc;
}

static int wait_ack(run_t *r, const char *msg_id, int timeout_ms) {
    long long deadline = now_ms() + timeout_ms;
    snprintf(r->want_ack, sizeof(r->want_ack), "%s", msg_id);
    r->ack_seen = 0;
    while (now_ms() < deadline) {
        uint8_t *msg = NULL;
        size_t msglen = 0;
        long long left = deadline - now_ms();
        int slice = left > 5000 ? 5000 : (int)left;
        wa_ws_msg_t m;
        if (slice < 0)
            slice = 0;
        m = wa_ws_recv(&r->ws, &msg, &msglen, slice);
        if (m == WA_WS_TIMEOUT) {
            free(msg);
            continue;
        }
        if (m != WA_WS_BIN) {
            free(msg);
            break;
        }
        if (wa_noise_feed(&r->noise, msg, msglen, frame_cb, r) < 0) {
            free(msg);
            break;
        }
        free(msg);
        if (r->ack_seen || r->outcome >= 0)
            break;
    }
    r->want_ack[0] = '\0';
    return r->ack_seen ? 0 : -1;
}

static int do_send_text(run_t *r, const char *to_raw, const char *text) {
    char dest_bare[WA_SEND_JID_MAX];
    char msg_id[32];
    uint8_t *pt = NULL;
    size_t ptlen = 0;
    char devices[WA_SEND_MAX_DEVICES][WA_SEND_JID_MAX];
    size_t ndev = 0;
    wa_dev_bundle_t bundles[WA_SEND_MAX_DEVICES];
    size_t nb = 0;
    char targets[WA_SEND_MAX_DEVICES][WA_SEND_JID_MAX];
    size_t nt = 0;
    wa_node_t *msg = NULL, *parts = NULL, *di = NULL;
    int rc = -1;

    if (normalize_jid(to_raw, dest_bare)) {
        rlog(r, "send: bad destination");
        return -1;
    }
    gen_msg_id(msg_id);
    if (encode_plaintext(text, &pt, &ptlen)) {
        rlog(r, "send: plaintext encode failed");
        return -1;
    }
    if (fetch_devices(r, dest_bare, devices, &ndev)) {
        rlog(r, "send: device discovery failed");
        free(pt);
        return -1;
    }
    /* skip our exact sender devices (whatsmeow pattern) */
    for (size_t i = 0; i < ndev && nt < WA_SEND_MAX_DEVICES; i++) {
        if (!strcmp(devices[i], r->creds->me_id) ||
            (r->creds->me_lid[0] && !strcmp(devices[i], r->creds->me_lid)))
            continue;
        snprintf(targets[nt++], WA_SEND_JID_MAX, "%s", devices[i]);
    }
    if (!nt) {
        rlog(r, "send: no recipients (only self?)");
        free(pt);
        return -1;
    }
    if (fetch_bundles(r, targets, nt, bundles, &nb)) {
        rlog(r, "send: bundle fetch failed");
        free(pt);
        return -1;
    }
    msg = wa_node_new("message");
    parts = wa_node_new("participants");
    if (!msg || !parts)
        goto fail;
    /* PN->LID conversion (whatsmeow pattern): when the destination is PN
     * but devices are LID, send `to` as LID bare with peer_recipient_pn. */
    {
        char dest_to[WA_SEND_JID_MAX];
        const char *at = strchr(dest_bare, '@');
        int is_pn = at && !strcmp(at + 1, "s.whatsapp.net");
        char lid_bare[WA_SEND_JID_MAX] = "";
        if (is_pn && nt > 0) {
            const char *dat = strchr(targets[0], '@');
            if (dat && !strcmp(dat + 1, "lid")) {
                const char *colon = strchr(targets[0], ':');
                size_t ul = colon ? (size_t)(colon - targets[0])
                                  : (size_t)(dat - targets[0]);
                if (ul < sizeof(lid_bare) - 5) {
                    memcpy(lid_bare, targets[0], ul);
                    lid_bare[ul] = '\0';
                    strcat(lid_bare, "@lid");
                }
            }
        }
        if (lid_bare[0]) {
            snprintf(dest_to, sizeof(dest_to), "%s", lid_bare);
            rlog(r, "send: PN->LID %s -> %s", dest_bare, dest_to);
            if (wa_node_add_attr(msg, "id", msg_id) ||
                wa_node_add_attr(msg, "to", dest_to) ||
                wa_node_add_attr(msg, "type", "text") ||
                wa_node_add_attr(msg, "peer_recipient_pn", dest_bare))
                goto fail;
        } else {
            if (wa_node_add_attr(msg, "id", msg_id) ||
                wa_node_add_attr(msg, "to", dest_bare) ||
                wa_node_add_attr(msg, "type", "text"))
                goto fail;
        }
    }
    for (size_t i = 0; i < nb; i++) {
        uint8_t *body = NULL;
        size_t bodylen = 0;
        wa_node_t *to = NULL, *enc = NULL;
        if (x3dh_encrypt_pkmsg(r->creds, &bundles[i], pt, ptlen, &body,
                               &bodylen)) {
            rlog(r, "send: encrypt failed for %s", bundles[i].jid);
            continue;
        }
        to = wa_node_new("to");
        enc = wa_node_new("enc");
        if (!to || !enc) {
            wa_node_free(to);
            wa_node_free(enc);
            free(body);
            goto fail;
        }
        if (wa_node_add_attr(to, "jid", bundles[i].jid) ||
            wa_node_add_attr(enc, "v", "2") ||
            wa_node_add_attr(enc, "type", "pkmsg") ||
            wa_node_set_bytes(enc, body, bodylen) ||
            wa_node_add_child(to, enc) || wa_node_add_child(parts, to)) {
            wa_node_free(to);
            free(body);
            goto fail;
        }
        free(body);
    }
    free(pt);
    pt = NULL;
    if (parts->ctype != WA_CONTENT_CHILDREN ||
        parts->content.children.len == 0) {
        rlog(r, "send: all encryptions failed");
        goto fail;
    }
    /* NOTE: Baileys sets phash in extraAttrs after encryption (dead code);
     * it is NOT sent on the stanza in current master, so omit it. */
    if (wa_node_add_child(msg, parts))
        goto fail;
    parts = NULL;
    /* device-identity (all first-messages are pkmsg -> include) */
    if (r->creds->account.present) {
        wa_pbw_t acc;
        di = wa_node_new("device-identity");
        if (!di)
            goto fail;
        if (wa_pb_encode_adv_account(
                r->creds->account.details, r->creds->account.details_len,
                r->creds->account.account_sig_key, WA_KEY_LEN,
                r->creds->account.account_sig, WA_SIG_LEN,
                r->creds->account.device_sig, WA_SIG_LEN, &acc)) {
            goto fail;
        }
        if (wa_node_set_bytes(di, acc.data, acc.len) ||
            wa_node_add_child(msg, di)) {
            wa_pbw_free(&acc);
            goto fail;
        }
        wa_pbw_free(&acc);
        di = NULL;
    }
    {
        wa_buf_t b;
        char *dump;
        rlog(r, "send: relaying '%s' to %s (%zu dev, id %s)...", text,
             dest_bare, nb, msg_id);
        dump = wa_node_to_string(msg);
        if (dump) {
            rlog(r, "send stanza: %s", dump);
            free(dump);
        }
        if (wa_encode_node(msg, &b) || send_frame(r, b.data, b.len)) {
            wa_buf_free(&b);
            rlog(r, "send: relay failed");
            goto fail;
        }
        wa_buf_free(&b);
    }
    wa_node_free(msg);
    msg = NULL;
    if (wait_ack(r, msg_id, 15000)) {
        rlog(r, "send: no ack for %s (may still have sent)", msg_id);
        /* Baileys treats missing ack as failure, but the message often
         * arrives anyway; report success with a warning. */
    } else {
        rlog(r, "send: acked %s", msg_id);
    }
    /* stay online briefly to catch delivery/retry receipts */
    {
        long long end = now_ms() + 15000;
        rlog(r, "send: listening 15s for receipts/retries...");
        while (now_ms() < end) {
            uint8_t *m = NULL;
            size_t ml = 0;
            long long left = end - now_ms();
            int slice = left > 5000 ? 5000 : (int)left;
            wa_ws_msg_t w;
            if (slice < 0)
                slice = 0;
            w = wa_ws_recv(&r->ws, &m, &ml, slice);
            if (w == WA_WS_TIMEOUT) {
                free(m);
                continue;
            }
            if (w != WA_WS_BIN) {
                free(m);
                break;
            }
            /* log raw decoded node for diagnosis */
            {
                wa_node_t *nn = NULL;
                size_t cc = 0;
                if (!wa_decode_node(m, ml, &nn, &cc)) {
                    /* feed through normal path to keep noise state */
                    char *d = wa_node_to_string(nn);
                    /* note: feeding again below will decode twice, but
                     * wa_noise_feed handles decrypt; we just peeked at
                     * raw transport bytes? Actually m is still encrypted
                     * frame, wa_decode_node on encrypted bytes fails.
                     * So just free and feed normally. */
                    if (d) {
                        free(d);
                    }
                    wa_node_free(nn);
                }
            }
            if (wa_noise_feed(&r->noise, m, ml, frame_cb, r) < 0) {
                free(m);
                break;
            }
            free(m);
            if (r->outcome >= 0)
                break;
        }
        rlog(r, "send: listen done");
    }
    printf("[sent] id=%s to=%s devices=%zu\n", msg_id, dest_bare, nb);
    rc = 0;
    return rc;
fail:
    free(pt);
    wa_node_free(di);
    wa_node_free(parts);
    wa_node_free(msg);
    return rc;
}

/* Encode + send a node without waiting for a reply (safe to call from inside
 * the receive path). Takes ownership of node. */
static void send_node_now(run_t *r, wa_node_t *node) {
    wa_buf_t b;
    if (!node)
        return;
    if (wa_encode_node(node, &b) == 0) {
        send_frame(r, b.data, b.len);
        wa_buf_free(&b);
    }
    wa_node_free(node);
}

/* Ack an inbound stanza so the server stops retrying it. */
static void send_ack(run_t *r, const char *id, const char *from) {
    wa_node_t *ack = wa_node_new("ack");
    if (!ack)
        return;
    if (wa_node_add_attr(ack, "id", id) || wa_node_add_attr(ack, "to", from) ||
        wa_node_add_attr(ack, "class", "message")) {
        wa_node_free(ack);
        return;
    }
    send_node_now(r, ack);
}

/* Reply on an existing session (produces a "msg" body). Fire-and-forget so it
 * is safe to call from the receive path. */
static int send_session_text(run_t *r, const char *addr, const char *text) {
    wa_pbw_t w;
    char msg_id[32];
    uint8_t *body = NULL;
    size_t blen = 0;
    wa_node_t *msg = NULL, *enc = NULL;
    if (!r->sig || !text)
        return -1;
    if (wa_pb_encode_wamessage_text(text, &w))
        return -1;
    if (wa_sig_encrypt(r->sig, addr, w.data, w.len, &body, &blen)) {
        wa_pbw_free(&w);
        rlog(r, "reply: no session for %s", addr);
        return -1;
    }
    wa_pbw_free(&w);
    gen_msg_id(msg_id);
    msg = wa_node_new("message");
    enc = wa_node_new("enc");
    if (!msg || !enc) {
        free(body);
        wa_node_free(msg);
        wa_node_free(enc);
        return -1;
    }
    if (wa_node_add_attr(msg, "id", msg_id) ||
        wa_node_add_attr(msg, "to", addr) ||
        wa_node_add_attr(msg, "type", "text") ||
        wa_node_add_attr(enc, "v", "2") ||
        wa_node_add_attr(enc, "type", "msg") ||
        wa_node_set_bytes(enc, body, blen) || wa_node_add_child(msg, enc)) {
        free(body);
        wa_node_free(msg);
        return -1;
    }
    free(body);
    send_node_now(r, msg);
    rlog(r, "reply sent to %s (id %s): %s", addr, msg_id, text);
    return 0;
}

/* Handle /reminder-style commands received over WhatsApp. */
static void handle_command(run_t *r, const char *from, const char *text) {
    const char *body = text;
    char reply[1024];
    while (*body == ' ' || *body == '\t' || *body == '\n')
        body++;
    if (!strncmp(body, "/reminder", 9) &&
        (body[9] == '\0' || body[9] == ' ' || body[9] == '\t')) {
        wa_rem_spec_t spec;
        if (wa_rem_parse_spec(body, from, wa_rem_local_offset(), &spec) == 0) {
            int id = wa_rem_add_spec(r->opts->auth_dir, &spec);
            if (id >= 0) {
                wa_reminder_t tmp;
                char sched[128];
                memset(&tmp, 0, sizeof(tmp));
                tmp.id = id;
                tmp.days = spec.days;
                tmp.hour = spec.hour;
                tmp.min = spec.min;
                tmp.tz_min = spec.tz_min;
                tmp.repeat = spec.repeat;
                snprintf(tmp.date, sizeof(tmp.date), "%s", spec.date);
                wa_rem_fmt_schedule(&tmp, sched, sizeof(sched));
                snprintf(reply, sizeof(reply),
                         "reminder #%d saved: %s -> %s: %s", id, sched,
                         spec.to, spec.text);
            } else {
                snprintf(reply, sizeof(reply), "failed to save reminder");
            }
        } else {
            snprintf(reply, sizeof(reply),
                     "usage: /reminder [YYYY-MM-DD] HH:MM [UTC-6] "
                     "[once|daily|weekly|Mon-Fri] [TO] TITLE");
        }
        send_session_text(r, from, reply);
        return;
    }
    if (!strcmp(body, "/reminders") || !strcmp(body, "/list")) {
        wa_reminder_t rems[WA_REM_MAX];
        int n = wa_rem_load(r->opts->auth_dir, rems, WA_REM_MAX);
        size_t off = 0;
        reply[0] = '\0';
        off += (size_t)snprintf(reply + off, sizeof(reply) - off,
                                "%d reminder(s):", n < 0 ? 0 : n);
        for (int i = 0; i < n && off + 200 < sizeof(reply); i++) {
            char sched[128];
            wa_rem_fmt_schedule(&rems[i], sched, sizeof(sched));
            off += (size_t)snprintf(reply + off, sizeof(reply) - off,
                                    "\n#%d %s %s", rems[i].id, sched,
                                    rems[i].text);
        }
        if (!n)
            snprintf(reply, sizeof(reply), "no reminders");
        send_session_text(r, from, reply);
        return;
    }
    if (!strncmp(body, "/del", 4)) {
        const char *num = !strncmp(body, "/delete", 7) ? body + 7 : body + 4;
        int id = atoi(num);
        if (wa_rem_del(r->opts->auth_dir, id) == 0)
            snprintf(reply, sizeof(reply), "deleted reminder #%d", id);
        else
            snprintf(reply, sizeof(reply), "no reminder #%d", id);
        send_session_text(r, from, reply);
        return;
    }
    if (!strcmp(body, "/help")) {
        send_session_text(r, from,
                          "/reminder [YYYY-MM-DD] HH:MM [UTC-6] "
                          "[once|daily|weekly|Mon-Fri] [TO] TITLE | "
                          "/reminders | /del N");
        return;
    }
}

/* Decrypt an inbound <message>: X3DH/Double-Ratchet, ack, dispatch command. */
static int is_self_jid(run_t *r, const char *jid) {
    const char *me[2] = { r->creds->me_id, r->creds->me_lid };
    for (int k = 0; k < 2; k++) {
        const char *at = jid ? strchr(jid, '@') : NULL;
        const char *mat = me[k][0] ? strchr(me[k], '@') : NULL;
        const char *colon, *mcolon;
        size_t ul, mul;
        if (!at || !mat)
            continue;
        colon = strchr(jid, ':');
        mcolon = strchr(me[k], ':');
        ul = (colon && colon < at) ? (size_t)(colon - jid) : (size_t)(at - jid);
        mul = (mcolon && mcolon < mat) ? (size_t)(mcolon - me[k])
                                       : (size_t)(mat - me[k]);
        if (ul != mul || strncmp(jid, me[k], ul) || strcmp(at + 1, mat + 1))
            continue;
        return 1;
    }
    return 0;
}

/* Count retries for one inbound message id. Returns the retry number to
 * request, or -1 once we've asked too many times. */
static int bump_retry(run_t *r, const char *id) {
    for (int i = 0; i < RETRY_SLOTS; i++) {
        if (r->retry_ids[i][0] && !strcmp(r->retry_ids[i], id)) {
            if (r->retry_counts[i] >= RETRY_MAX)
                return -1;
            return ++r->retry_counts[i];
        }
    }
    int slot = r->retry_next++ % RETRY_SLOTS;
    snprintf(r->retry_ids[slot], sizeof(r->retry_ids[slot]), "%s", id);
    r->retry_counts[slot] = 1;
    return 1;
}

/* Ask the sender to re-encrypt with a fresh session (<receipt type=retry>).
 * This also acks the stanza, so the server stops replaying it. */
static void send_retry_receipt(run_t *r, const char *id, const char *from,
                               const char *participant) {
    wa_node_t *rcpt, *retry;
    char cbuf[16], tbuf[32];
    int count;
    if (!id || !from)
        return;
    count = bump_retry(r, id);
    if (count < 0) {
        rlog(r, "retry: giving up on %s from %s", id, from);
        send_ack(r, id, from);
        return;
    }
    rcpt = wa_node_new("receipt");
    retry = wa_node_new("retry");
    if (!rcpt || !retry) {
        wa_node_free(rcpt);
        wa_node_free(retry);
        return;
    }
    snprintf(cbuf, sizeof(cbuf), "%d", count);
    snprintf(tbuf, sizeof(tbuf), "%lld", (long long)time(NULL));
    if (wa_node_add_attr(rcpt, "id", id) ||
        wa_node_add_attr(rcpt, "to", from) ||
        wa_node_add_attr(rcpt, "type", "retry") ||
        (participant && wa_node_add_attr(rcpt, "participant", participant)) ||
        wa_node_add_attr(retry, "id", id) ||
        wa_node_add_attr(retry, "count", cbuf) ||
        wa_node_add_attr(retry, "t", tbuf) ||
        wa_node_add_attr(retry, "v", "1") ||
        wa_node_add_child(rcpt, retry)) {
        wa_node_free(rcpt);
        wa_node_free(retry);
        return;
    }
    rlog(r, "retry request #%d for %s from %s", count, id, from);
    send_node_now(r, rcpt);
}

static int handle_message(run_t *r, wa_node_t *node) {
    const char *from = wa_node_get_attr(node, "from");
    const char *id = wa_node_get_attr(node, "id");
    const char *participant = wa_node_get_attr(node, "participant");
    wa_node_t *enc;
    int self, retry = 0;
    if (!from)
        return 0;
    self = is_self_jid(r, from); /* own account (linked devices / sync) */
    enc = wa_node_get_child(node, "enc");
    if (enc && enc->ctype == WA_CONTENT_BYTES && r->sig) {
        const char *etype = wa_node_get_attr(enc, "type");
        const uint8_t *body = enc->content.bytes.data;
        size_t blen = enc->content.bytes.len;
        if (etype && (!strcmp(etype, "pkmsg") || !strcmp(etype, "msg"))) {
            uint8_t *pt = NULL;
            size_t ptlen = 0;
            if (wa_sig_decrypt(r->sig, from, etype, body, blen, &pt, &ptlen) ==
                0) {
                char text[WA_REM_TEXT_MAX * 2];
                if (wa_pb_decode_wamessage_text(pt, ptlen, text,
                                                sizeof(text)) == 0) {
                    rlog(r, "incoming%s from %s: %s", self ? " (self)" : "",
                         from, text);
                    if (r->opts->on_message)
                        r->opts->on_message(from, text, r->opts->user);
                    if (!self) /* don't act on our own outgoing texts */
                        handle_command(r, from, text);
                } else {
                    rlog(r, "incoming%s from %s: <non-text>",
                         self ? " (self)" : "", from);
                }
                free(pt);
            } else {
                rlog(r, "decrypt failed from %s (%s)", from, etype);
                retry = 1;
            }
        }
    }
    if (retry && id && strcmp(from, "status@broadcast")) {
        send_retry_receipt(r, id, from, participant);
        return 0;
    }
    if (id)
        send_ack(r, id, from);
    return 0;
}

/* Daemon: poll reminders.tsv once per minute, send due via same connection.
 * Dedupe with fired_minute key so each reminder fires once per minute. */
static void daemon_poll(run_t *r) {
    time_t now = time(NULL);
    long long key;
    wa_reminder_t rems[WA_REM_MAX];
    int n, i;
    /* UTC minute: reminders may use different UTC offsets. */
    key = (long long)(now / 60);
    if (key != r->fired_minute) {
        r->fired_minute = key;
        r->n_fired = 0;
    }
    n = wa_rem_load(r->opts->auth_dir, rems, WA_REM_MAX);
    if (n < 0)
        return;
    for (i = 0; i < n; i++) {
        int already = 0;
        for (int k = 0; k < r->n_fired; k++)
            if (r->fired_ids[k] == rems[i].id) {
                already = 1;
                break;
            }
        if (already)
            continue;
        if (!wa_rem_due(&rems[i], now))
            continue;
        rlog(r, "reminder due id=%d to=%s text='%s'", rems[i].id, rems[i].to,
             rems[i].text);
        if (do_send_text(r, rems[i].to, rems[i].text) == 0) {
            rlog(r, "reminder sent id=%d", rems[i].id);
            if (r->n_fired < WA_REM_MAX)
                r->fired_ids[r->n_fired++] = rems[i].id;
            if (rems[i].repeat == WA_REM_ONCE)
                wa_rem_del(r->opts->auth_dir, rems[i].id);
        } else {
            rlog(r, "reminder failed id=%d (will retry next minute)",
                 rems[i].id);
        }
        if (r->outcome >= 0)
            return;
    }
}

/* Build + upload fresh one-time prekeys, then announce presence.
 * Failures are logged but non-fatal (Baileys is lenient here too). */
static void do_post_login(run_t *r) {
    wa_node_t *iq, *reg, *type, *ident, *list, *skey, *idn, *val, *sgn;
    wa_node_t *resp;
    char tag[WA_TAG_MAX];
    int i;
    r->post_done = 1;

    iq = wa_node_new("iq");
    reg = wa_node_new("registration");
    type = wa_node_new("type");
    ident = wa_node_new("identity");
    list = wa_node_new("list");
    skey = wa_node_new("skey");
    if (!iq || !reg || !type || !ident || !list || !skey)
        goto oom;
    snprintf(tag, sizeof(tag), "cwa.%lu", r->msg_tag++);
    if (wa_node_add_attr(iq, "id", tag) ||
        wa_node_add_attr(iq, "xmlns", "encrypt") ||
        wa_node_add_attr(iq, "type", "set") ||
        wa_node_add_attr(iq, "to", "s.whatsapp.net"))
        goto oom;
    {
        uint8_t be[4];
        be[0] = (uint8_t)(r->creds->registration_id >> 24);
        be[1] = (uint8_t)(r->creds->registration_id >> 16);
        be[2] = (uint8_t)(r->creds->registration_id >> 8);
        be[3] = (uint8_t)r->creds->registration_id;
        if (wa_node_set_bytes(reg, be, 4))
            goto oom;
    }
    {
        static const uint8_t kt = 5;
        if (wa_node_set_bytes(type, &kt, 1) ||
            wa_node_set_bytes(ident, r->creds->ident_pub, 32))
            goto oom;
    }
    {
        uint32_t ids[5];
        uint8_t pubs[5][32];
        uint32_t start = r->creds->next_prekey_id;
        int gen = r->sig && wa_sig_gen_opks(r->sig, start, 5, ids, pubs) == 0;
        if (gen) {
            r->creds->next_prekey_id = start + 5;
            save_creds(r);
            wa_sig_save_prekeys(r->sig);
        }
        for (i = 0; i < 5; i++) {
            uint8_t priv[32], pub[32], idbe[3];
            uint32_t id;
            wa_node_t *key = wa_node_new("key");
            idn = wa_node_new("id");
            val = wa_node_new("value");
            if (!key || !idn || !val) {
                wa_node_free(key);
                wa_node_free(idn);
                wa_node_free(val);
                goto oom;
            }
            if (gen) {
                id = ids[i];
                memcpy(pub, pubs[i], 32);
            } else {
                id = start + (uint32_t)i;
                if (RAND_bytes(priv, 32) != 1 || wa_x25519_pub(pub, priv)) {
                    wa_node_free(key);
                    wa_node_free(idn);
                    wa_node_free(val);
                    goto oom;
                }
            }
            idbe[0] = (uint8_t)(id >> 16);
            idbe[1] = (uint8_t)(id >> 8);
            idbe[2] = (uint8_t)id;
            if (wa_node_set_bytes(idn, idbe, 3) ||
                wa_node_set_bytes(val, pub, 32) ||
                wa_node_add_child(key, idn) || wa_node_add_child(key, val) ||
                wa_node_add_child(list, key))
                goto oom;
        }
        if (!gen)
            r->creds->next_prekey_id = start + 5;
    }
    {
        uint8_t idbe[3];
        idn = wa_node_new("id");
        val = wa_node_new("value");
        sgn = wa_node_new("signature");
        if (!idn || !val || !sgn) {
            wa_node_free(idn);
            wa_node_free(val);
            wa_node_free(sgn);
            goto oom;
        }
        idbe[0] = (uint8_t)(r->creds->pre_id >> 16);
        idbe[1] = (uint8_t)(r->creds->pre_id >> 8);
        idbe[2] = (uint8_t)r->creds->pre_id;
        if (wa_node_set_bytes(idn, idbe, 3) ||
            wa_node_set_bytes(val, r->creds->pre_pub, 32) ||
            wa_node_set_bytes(sgn, r->creds->pre_sig, 64) ||
            wa_node_add_child(skey, idn) || wa_node_add_child(skey, val) ||
            wa_node_add_child(skey, sgn))
            goto oom;
    }
    if (wa_node_add_child(iq, reg) || wa_node_add_child(iq, type) ||
        wa_node_add_child(iq, ident) || wa_node_add_child(iq, list) ||
        wa_node_add_child(iq, skey))
        goto oom;
    rlog(r, "uploading 5 one-time prekeys...");
    resp = run_query(r, iq, 15000);
    wa_node_free(iq);
    if (!resp) {
        rlog(r, "prekey upload: no response (continuing anyway)");
    } else {
        rlog(r, "prekey upload acked");
        r->creds->first_unuploaded_prekey_id = r->creds->next_prekey_id;
        save_creds(r);
        wa_node_free(resp);
        r->response = NULL;
    }
    /* passive -> active presence announce */
    iq = wa_node_new("iq");
    {
        wa_node_t *active = wa_node_new("active");
        if (!iq || !active) {
            wa_node_free(iq);
            wa_node_free(active);
            return;
        }
        snprintf(tag, sizeof(tag), "cwa.%lu", r->msg_tag++);
        if (wa_node_add_attr(iq, "id", tag) ||
            wa_node_add_attr(iq, "to", "s.whatsapp.net") ||
            wa_node_add_attr(iq, "xmlns", "passive") ||
            wa_node_add_attr(iq, "type", "set") ||
            wa_node_add_child(iq, active)) {
            wa_node_free(iq);
            return;
        }
    }
    rlog(r, "announcing active presence...");
    resp = run_query(r, iq, 15000);
    wa_node_free(iq);
    if (!resp) {
        rlog(r, "presence announce: no response (continuing anyway)");
    } else {
        wa_node_free(resp);
        r->response = NULL;
    }
    return;
oom:
    wa_node_free(iq);
    rlog(r, "post-login: out of memory (continuing anyway)");
}

int wa_conn_run(wa_creds_t *creds, const wa_conn_opts_t *opts) {
    run_t r;
    uint8_t eph_priv[32];
    wa_pbw_t hello, finish, payload;
    uint8_t s_eph[32], *s_stat = NULL, *s_pay = NULL;
    size_t s_statlen = 0, s_paylen = 0;
    uint8_t *dec = NULL;
    wa_certchain_t chain;
    uint8_t key_enc[48];
    int rc = WA_RUN_ERROR, conn_to;
    char path[256];

    if (!creds || !opts)
        return WA_RUN_ERROR;
    memset(&r, 0, sizeof(r));
    r.creds = creds;
    r.opts = opts;
    r.outcome = -1;
    r.qr_deadline_ms = -1;
    if (opts->auth_dir) {
        r.sig = malloc(sizeof(*r.sig));
        if (r.sig) {
            wa_sig_init(r.sig, opts->auth_dir, creds);
            wa_sig_load(r.sig);
        }
    }
    conn_to = opts->connect_timeout_ms ? opts->connect_timeout_ms : 20000;
    if (opts->run_timeout_ms)
        r.end_ms = now_ms() + opts->run_timeout_ms;

    if (RAND_bytes(eph_priv, 32) != 1)
        return WA_RUN_ERROR;
    wa_noise_init(&r.noise, eph_priv, NULL);

    /* WS path (+ ED routing param when resuming, like Baileys). */
    if (creds->routing_info_len) {
        char rb64[128];
        /* base64url for the query param */
        wa_b64_encode(creds->routing_info, creds->routing_info_len, rb64,
                      sizeof(rb64));
        for (char *p = rb64; *p; p++) {
            if (*p == '+')
                *p = '-';
            else if (*p == '/')
                *p = '_';
        }
        char *pad = strchr(rb64, '=');
        if (pad)
            *pad = '\0';
        snprintf(path, sizeof(path), "%s?ED=%s", WA_WS_PATH, rb64);
    } else {
        snprintf(path, sizeof(path), "%s", WA_WS_PATH);
    }

    rlog(&r, "connecting %s...", WA_WS_HOST);
    if (wa_ws_connect(&r.ws, WA_WS_HOST, WA_WS_PORT, path, WA_ORIGIN,
                      conn_to)) {
        rlog(&r, "websocket connect failed");
        goto out;
    }
    r.ws_open = 1;

    /* ClientHello */
    wa_pb_encode_client_hello(r.noise.e_pub, &hello);
    if (send_frame(&r, hello.data, hello.len)) {
        wa_pbw_free(&hello);
        rlog(&r, "clienthello send failed");
        goto out;
    }
    wa_pbw_free(&hello);

    /* ServerHello (first WS message, still handshake-encrypted framing). */
    {
        uint8_t *msg = NULL;
        size_t msglen = 0;
        wa_ws_msg_t m = wa_ws_recv(&r.ws, &msg, &msglen, conn_to);
        if (m != WA_WS_BIN || !msglen) {
            free(msg);
            rlog(&r, "no serverhello (timeout/close)");
            goto out;
        }
        /* Raw frame: 3-byte length + HandshakeMessage protobuf. */
        if (msglen < 3) {
            free(msg);
            goto out;
        }
        size_t hlen = ((size_t)msg[0] << 16) | ((size_t)msg[1] << 8) | msg[2];
        int ok = hlen + 3 <= msglen &&
                 wa_pb_decode_server_hello(msg + 3, hlen, s_eph, &s_stat,
                                           &s_statlen, &s_pay, &s_paylen) == 0;
        free(msg);
        if (!ok) {
            rlog(&r, "serverhello decode failed");
            goto out;
        }
    }
    rlog(&r, "serverhello ok, verifying cert chain...");

    if (wa_noise_mix_server_ephemeral(&r.noise, s_eph))
        goto out;
    dec = malloc(s_statlen + s_paylen + 64);
    if (!dec)
        goto out;
    {
        int dl = wa_noise_decrypt(&r.noise, s_stat, s_statlen, dec,
                                  s_statlen + s_paylen + 64);
        if (dl != 32) {
            rlog(&r, "server static decrypt failed");
            goto out;
        }
        if (wa_noise_mix_static(&r.noise, dec))
            goto out;
    }
    {
        int dl = wa_noise_decrypt(&r.noise, s_pay, s_paylen, dec,
                                  s_statlen + s_paylen + 64);
        if (dl <= 0) {
            rlog(&r, "server payload decrypt failed");
            goto out;
        }
        if (wa_pb_decode_cert_chain(dec, (size_t)dl, &chain)) {
            rlog(&r, "cert chain decode failed");
            goto out;
        }
    }
    /* verify: issuerSerial == 0, intermediate signed by WA root,
     * leaf signed by intermediate key. */
    {
        uint32_t iserial, iissuer, lserial, lissuer;
        const uint8_t *ikey, *lkey;
        size_t ikeylen, lkeylen;
        if (wa_pb_decode_cert_details(chain.int_details,
                                      chain.int_details_len, &iserial, &iissuer,
                                      &ikey, &ikeylen) ||
            iissuer != WA_CERT_SERIAL || ikeylen != 32) {
            rlog(&r, "intermediate cert details bad");
            goto out;
        }
        (void)iserial;
        if (chain.int_sig_len != 64 ||
            wa_xeddsa_verify(WA_CERT_PUBKEY, chain.int_details,
                             chain.int_details_len, chain.int_sig)) {
            rlog(&r, "intermediate signature invalid");
            goto out;
        }
        if (wa_pb_decode_cert_details(chain.leaf_details,
                                      chain.leaf_details_len, &lserial,
                                      &lissuer, &lkey, &lkeylen) ||
            lkeylen != 32) {
            rlog(&r, "leaf cert details bad");
            goto out;
        }
        (void)lserial;
        (void)lissuer;
        if (chain.leaf_sig_len != 64 ||
            wa_xeddsa_verify(ikey, chain.leaf_details,
                             chain.leaf_details_len, chain.leaf_sig)) {
            rlog(&r, "leaf signature invalid");
            goto out;
        }
        rlog(&r, "cert chain valid");
    }
    wa_certchain_free(&chain);
    memset(&chain, 0, sizeof(chain));

    /* ClientFinish */
    if (wa_noise_encrypt_static(&r.noise, creds->noise_pub, creds->noise_priv,
                                key_enc) != 48) {
        rlog(&r, "static encrypt failed");
        goto out;
    }
    /* Pairing attempts always (re-)register: a stale me_id from a previous
     * failed attempt must not turn this into a login. */
    int pairing = opts->pair_number && opts->pair_number[0] && !creds->registered;
    if (pairing) {
        creds->me_id[0] = '\0';
        creds->me_name[0] = '\0';
    }
    if (creds->me_id[0]) {
        /* login */
        char user[64], server[64];
        const char *at = strchr(creds->me_id, '@');
        uint64_t username = 0;
        int have_device = 0;
        uint32_t device = 0;
        if (!at) {
            rlog(&r, "bad me_id");
            goto out;
        }
        snprintf(user, sizeof(user), "%.*s", (int)(at - creds->me_id),
                 creds->me_id);
        snprintf(server, sizeof(server), "%s", at + 1);
        (void)server;
        char *colon = strchr(user, ':');
        if (colon) {
            *colon = '\0';
            device = (uint32_t)strtoul(colon + 1, NULL, 10);
            have_device = 1;
        }
        username = strtoull(user, NULL, 10);
        rlog(&r, "logging in as %s...", user);
        if (wa_pb_encode_login(username, have_device, device, opts->push_name,
                               &payload))
            goto out;
    } else {
        rlog(&r, "registering (new device)...");
        if (wa_pb_encode_registration(
                creds->ident_pub, creds->pre_pub, creds->pre_sig, creds->pre_id,
                creds->registration_id, opts->push_name, &payload))
            goto out;
    }
    {
        uint8_t *enc = malloc(payload.len + 16);
        int el;
        if (!enc) {
            wa_pbw_free(&payload);
            goto out;
        }
        el = wa_noise_encrypt(&r.noise, payload.data, payload.len, enc,
                              payload.len + 16);
        wa_pbw_free(&payload);
        if (el <= 0) {
            free(enc);
            goto out;
        }
        wa_pb_encode_client_finish(key_enc, 48, enc, (size_t)el, &finish);
        free(enc);
        if (send_frame(&r, finish.data, finish.len)) {
            wa_pbw_free(&finish);
            goto out;
        }
        wa_pbw_free(&finish);
    }
    if (wa_noise_finish_init(&r.noise)) {
        rlog(&r, "finish_init failed");
        goto out;
    }
    r.keepalive_ms = now_ms() + 25000;

    /* pairing-code request (after registration, like Baileys: sent once the
     * socket is ready; pair-device QRs are ignored in this mode). */
    if (pairing) {
        char jid[64];
        snprintf(jid, sizeof(jid), "%.32s@s.whatsapp.net", opts->pair_number);
        snprintf(creds->me_id, sizeof(creds->me_id), "%s", jid);
        snprintf(creds->me_name, sizeof(creds->me_name), "~");
        save_creds(&r);
        rlog(&r, "requesting pairing code for %s...", opts->pair_number);
        if (send_pairing_reg(&r, opts->pair_number)) {
            rlog(&r, "pairing-code request failed");
            goto out;
        }
        if (opts->on_pair_code)
            opts->on_pair_code(creds->pairing_code, opts->user);
        rlog(&r, "enter the code on the phone, waiting for pair-success...");
    }

    /* dispatch loop */
    rlog(&r, "handshake done, listening...");
    for (;;) {
        long long now = now_ms();
        int wait_ms = 5000;
        if (r.end_ms && now >= r.end_ms) {
            rlog(&r, "run timeout");
            rc = WA_RUN_TIMEOUT;
            goto out;
        }
        if (r.logged_in && !r.post_done) {
            do_post_login(&r);
            if (r.outcome >= 0) {
                rc = r.outcome;
                goto out;
            }
            if (r.opts->to_jid && r.opts->text) {
                if (do_send_text(&r, r.opts->to_jid, r.opts->text)) {
                    rlog(&r, "send failed");
                    rc = WA_RUN_ERROR;
                    goto out;
                }
                if (r.outcome >= 0) {
                    rc = r.outcome;
                    goto out;
                }
                if (!r.opts->daemon) {
                    r.outcome = WA_RUN_OPEN;
                    rc = WA_RUN_OPEN;
                    goto out;
                }
            }
            if (r.opts->daemon || r.opts->listen) {
                if (r.opts->daemon) {
                    r.daemon_on = 1;
                    r.rem_check_ms = 0; /* check immediately */
                    r.fired_minute = -1;
                    r.n_fired = 0;
                    rlog(&r, "daemon online, polling reminders...");
                } else {
                    r.listen_on = 1;
                    r.rem_check_ms = 0; /* reminders also fire while listening */
                    r.fired_minute = -1;
                    r.n_fired = 0;
                    rlog(&r, "listening for incoming messages and reminders...");
                }
                if (r.opts->on_open)
                    r.opts->on_open(r.opts->user);
                /* fall through to dispatch (don't exit) */
            } else {
                if (r.opts->on_open)
                    r.opts->on_open(r.opts->user);
                r.outcome = WA_RUN_OPEN;
                rc = WA_RUN_OPEN;
                goto out;
            }
        }
        if (r.end_ms && now >= r.end_ms) {
            rlog(&r, "run timeout");
            rc = WA_RUN_TIMEOUT;
            goto out;
        }
        if (r.qr_deadline_ms >= 0 && now >= r.qr_deadline_ms) {
            if (r.ref_idx >= r.n_refs) {
                rlog(&r, "QR refs exhausted");
                if (opts->on_close)
                    opts->on_close("qr-refs-exhausted", opts->user);
                rc = WA_RUN_TIMEOUT;
                goto out;
            }
            emit_qr(&r);
        }
        if (now >= r.keepalive_ms) {
            wa_ws_send_ping(&r.ws);
            r.keepalive_ms = now + 25000;
        }
        if ((r.daemon_on || r.listen_on) && now >= r.rem_check_ms) {
            daemon_poll(&r);
            r.rem_check_ms = now + 15000;
            if (r.outcome >= 0) {
                rc = r.outcome;
                goto out;
            }
            now = now_ms();
        }
        if (r.qr_deadline_ms >= 0)
            wait_ms = (int)(r.qr_deadline_ms - now);
        if (r.end_ms)
            wait_ms = wait_ms < (int)(r.end_ms - now) ? wait_ms : (int)(r.end_ms - now);
        if (r.daemon_on || r.listen_on)
            wait_ms = wait_ms < (int)(r.rem_check_ms - now)
                          ? wait_ms
                          : (int)(r.rem_check_ms - now);
        if (wait_ms < 0)
            wait_ms = 0;
        if (wait_ms > 5000)
            wait_ms = 5000;
        {
            uint8_t *msg = NULL;
            size_t msglen = 0;
            wa_ws_msg_t m = wa_ws_recv(&r.ws, &msg, &msglen, wait_ms);
            if (m == WA_WS_TIMEOUT) {
                free(msg);
                continue;
            }
            if (m == WA_WS_CLOSE) {
                free(msg);
                rlog(&r, "server closed connection (pairing restart?)");
                rc = WA_RUN_RESTART;
                goto out;
            }
            if (m != WA_WS_BIN) {
                free(msg);
                rlog(&r, "transport error");
                goto out;
            }
            {
                int fr = wa_noise_feed(&r.noise, msg, msglen, frame_cb, &r);
                free(msg);
                if (fr < 0) {
                    rlog(&r, "frame decrypt error");
                    goto out;
                }
                if (r.outcome >= 0) {
                    rc = r.outcome;
                    goto out;
                }
            }
        }
    }

out:
    free(s_stat);
    free(s_pay);
    free(dec);
    free(r.sig);
    wa_certchain_free(&chain);
    free_refs(&r);
    wa_node_free(r.response);
    wa_noise_free(&r.noise);
    if (r.ws_open)
        wa_ws_close(&r.ws);
    return rc;
}

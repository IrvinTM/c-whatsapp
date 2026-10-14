/* wa_socket.c — connection flow (see wa_socket.h). */
#define _POSIX_C_SOURCE 200809L

#include "wa_socket.h"
#include "wa_crypto.h"
#include "wa_noise.h"
#include "wa_pairing.h"
#include "wa_pb.h"
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
    for (i = 0; i < 5; i++) {
        /* TODO(Phase 5b): persist these one-time prekeys (pub+priv) to the
         * auth dir so future inbound sessions can complete X3DH. */
        uint8_t priv[32], pub[32], idbe[3];
        uint32_t id = r->creds->next_prekey_id++;
        wa_node_t *key = wa_node_new("key");
        idn = wa_node_new("id");
        val = wa_node_new("value");
        if (!key || !idn || !val) {
            wa_node_free(key);
            wa_node_free(idn);
            wa_node_free(val);
            goto oom;
        }
        if (RAND_bytes(priv, 32) != 1 || wa_x25519_pub(pub, priv)) {
            wa_node_free(key);
            wa_node_free(idn);
            wa_node_free(val);
            goto oom;
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
            if (r.opts->on_open)
                r.opts->on_open(r.opts->user);
            r.outcome = WA_RUN_OPEN;
            rc = WA_RUN_OPEN;
            goto out;
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
        if (r.qr_deadline_ms >= 0)
            wait_ms = (int)(r.qr_deadline_ms - now);
        if (r.end_ms)
            wait_ms = wait_ms < (int)(r.end_ms - now) ? wait_ms : (int)(r.end_ms - now);
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
    wa_certchain_free(&chain);
    free_refs(&r);
    wa_node_free(r.response);
    wa_noise_free(&r.noise);
    if (r.ws_open)
        wa_ws_close(&r.ws);
    return rc;
}

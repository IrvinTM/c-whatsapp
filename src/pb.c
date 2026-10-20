/* wa_pb.c — minimal protobuf codec (see wa_pb.h). */
#include "wa_pb.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

void wa_pbw_init(wa_pbw_t *w) {
    w->data = NULL;
    w->len = w->cap = 0;
}

void wa_pbw_free(wa_pbw_t *w) {
    free(w->data);
    w->data = NULL;
    w->len = w->cap = 0;
}

int wa_pbw_reserve(wa_pbw_t *w, size_t extra) {
    if (w->len + extra <= w->cap)
        return 0;
    size_t ncap = w->cap ? w->cap * 2 : 128;
    while (ncap < w->len + extra)
        ncap *= 2;
    uint8_t *nd = realloc(w->data, ncap);
    if (!nd)
        return -1;
    w->data = nd;
    w->cap = ncap;
    return 0;
}

int wa_pbw_raw(wa_pbw_t *w, const uint8_t *d, size_t n) {
    if (wa_pbw_reserve(w, n))
        return -1;
    memcpy(w->data + w->len, d, n);
    w->len += n;
    return 0;
}

int wa_pbw_varint(wa_pbw_t *w, uint64_t v) {
    uint8_t tmp[10];
    size_t n = 0;
    do {
        tmp[n++] = (uint8_t)((v & 0x7f) | (v > 0x7f ? 0x80 : 0));
        v >>= 7;
    } while (v);
    return wa_pbw_raw(w, tmp, n);
}

int wa_pbw_tag(wa_pbw_t *w, uint32_t field, uint32_t wire) {
    return wa_pbw_varint(w, ((uint64_t)field << 3) | wire);
}

int wa_pbw_u32(wa_pbw_t *w, uint32_t field, uint32_t v) {
    return wa_pbw_tag(w, field, WA_PB_VARINT) || wa_pbw_varint(w, v) ? -1 : 0;
}

int wa_pbw_u64(wa_pbw_t *w, uint32_t field, uint64_t v) {
    return wa_pbw_tag(w, field, WA_PB_VARINT) || wa_pbw_varint(w, v) ? -1 : 0;
}

int wa_pbw_bool(wa_pbw_t *w, uint32_t field, int v) {
    return wa_pbw_u32(w, field, v ? 1 : 0);
}

int wa_pbw_bytes(wa_pbw_t *w, uint32_t field, const uint8_t *d, size_t n) {
    if (!d && n)
        return -1;
    if (wa_pbw_tag(w, field, WA_PB_LEN) || wa_pbw_varint(w, n) ||
        wa_pbw_raw(w, d, n))
        return -1;
    return 0;
}

int wa_pbw_str(wa_pbw_t *w, uint32_t field, const char *s) {
    if (!s)
        return -1;
    return wa_pbw_bytes(w, field, (const uint8_t *)s, strlen(s));
}

int wa_pbw_msg(wa_pbw_t *w, uint32_t field, const wa_pbw_t *sub) {
    return wa_pbw_bytes(w, field, sub->data, sub->len);
}

/* ---------------- reader ---------------- */

static int rd_varint(wa_pbr_t *r, uint64_t *out) {
    uint64_t v = 0;
    int shift = 0;
    for (int i = 0; i < 10; i++) {
        uint8_t b;
        if (r->pos >= r->len)
            return -1;
        b = r->p[r->pos++];
        v |= (uint64_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) {
            *out = v;
            return 0;
        }
        shift += 7;
    }
    return -1;
}

int wa_pbr_next(wa_pbr_t *r, wa_pbf_t *f) {
    uint64_t tag;
    if (r->pos >= r->len)
        return 0;
    if (rd_varint(r, &tag))
        return -1;
    f->field = (uint32_t)(tag >> 3);
    f->wire = (uint32_t)(tag & 7);
    f->varint = 0;
    f->data = NULL;
    f->datalen = 0;
    if (f->field == 0)
        return -1;
    switch (f->wire) {
    case WA_PB_VARINT:
        return rd_varint(r, &f->varint) ? -1 : 1;
    case WA_PB_64BIT:
        if (r->pos + 8 > r->len)
            return -1;
        r->pos += 8;
        return 1;
    case WA_PB_LEN: {
        uint64_t n;
        if (rd_varint(r, &n) || r->pos + n > r->len)
            return -1;
        f->data = r->p + r->pos;
        f->datalen = (size_t)n;
        r->pos += (size_t)n;
        return 1;
    }
    case WA_PB_32BIT:
        if (r->pos + 4 > r->len)
            return -1;
        r->pos += 4;
        return 1;
    default:
        return -1;
    }
}

/* ---------------- HandshakeMessage ---------------- */

int wa_pb_encode_client_hello(const uint8_t eph[32], wa_pbw_t *out) {
    wa_pbw_t hello;
    wa_pbw_init(&hello);
    wa_pbw_init(out);
    if (wa_pbw_bytes(&hello, 1, eph, 32) ||
        wa_pbw_bytes(out, 2, hello.data, hello.len)) {
        wa_pbw_free(&hello);
        wa_pbw_free(out);
        return -1;
    }
    wa_pbw_free(&hello);
    return 0;
}

int wa_pb_encode_client_finish(const uint8_t *st, size_t stlen,
                               const uint8_t *pay, size_t paylen,
                               wa_pbw_t *out) {
    wa_pbw_t fin;
    wa_pbw_init(&fin);
    wa_pbw_init(out);
    if (wa_pbw_bytes(&fin, 1, st, stlen) ||
        wa_pbw_bytes(&fin, 2, pay, paylen) ||
        wa_pbw_bytes(out, 4, fin.data, fin.len)) {
        wa_pbw_free(&fin);
        wa_pbw_free(out);
        return -1;
    }
    wa_pbw_free(&fin);
    return 0;
}

static uint8_t *dup_bytes(const uint8_t *d, size_t n) {
    uint8_t *o = malloc(n ? n : 1);
    if (!o)
        return NULL;
    if (n)
        memcpy(o, d, n);
    return o;
}

int wa_pb_decode_server_hello(const uint8_t *msg, size_t len,
                              uint8_t eph[32], uint8_t **stat, size_t *statlen,
                              uint8_t **pay, size_t *paylen) {
    wa_pbr_t r = { msg, len, 0 };
    wa_pbf_t f;
    int rc, found = 0;
    *stat = NULL;
    *pay = NULL;
    while ((rc = wa_pbr_next(&r, &f)) == 1) {
        if (f.field == 3 && f.wire == WA_PB_LEN) { /* serverHello */
            wa_pbr_t s = { f.data, f.datalen, 0 };
            wa_pbf_t g;
            int grc;
            found = 1;
            while ((grc = wa_pbr_next(&s, &g)) == 1) {
                if (g.wire != WA_PB_LEN)
                    continue;
                if (g.field == 1 && g.datalen == 32)
                    memcpy(eph, g.data, 32);
                else if (g.field == 2) {
                    free(*stat);
                    *stat = dup_bytes(g.data, g.datalen);
                    *statlen = g.datalen;
                    if (!*stat)
                        return -1;
                } else if (g.field == 3) {
                    free(*pay);
                    *pay = dup_bytes(g.data, g.datalen);
                    *paylen = g.datalen;
                    if (!*pay) {
                        free(*stat);
                        *stat = NULL;
                        return -1;
                    }
                }
            }
            if (grc < 0)
                goto fail;
        }
    }
    if (rc < 0 || !found || !*stat || !*pay)
        goto fail;
    return 0;
fail:
    free(*stat);
    free(*pay);
    *stat = *pay = NULL;
    return -1;
}

/* ---------------- CertChain ---------------- */

void wa_certchain_free(wa_certchain_t *c) {
    if (!c)
        return;
    free(c->leaf_details);
    free(c->leaf_sig);
    free(c->int_details);
    free(c->int_sig);
    memset(c, 0, sizeof(*c));
}

static int decode_noise_cert(const uint8_t *d, size_t n, uint8_t **details,
                             size_t *details_len, uint8_t **sig,
                             size_t *sig_len) {
    wa_pbr_t r = { d, n, 0 };
    wa_pbf_t f;
    int rc;
    *details = NULL;
    *sig = NULL;
    while ((rc = wa_pbr_next(&r, &f)) == 1) {
        if (f.wire != WA_PB_LEN)
            continue;
        if (f.field == 1) {
            free(*details);
            *details = dup_bytes(f.data, f.datalen);
            *details_len = f.datalen;
            if (!*details)
                return -1;
        } else if (f.field == 2) {
            free(*sig);
            *sig = dup_bytes(f.data, f.datalen);
            *sig_len = f.datalen;
            if (!*sig) {
                free(*details);
                *details = NULL;
                return -1;
            }
        }
    }
    if (rc < 0 || !*details || !*sig) {
        free(*details);
        free(*sig);
        *details = *sig = NULL;
        return -1;
    }
    return 0;
}

int wa_pb_decode_cert_chain(const uint8_t *msg, size_t len,
                            wa_certchain_t *out) {
    wa_pbr_t r = { msg, len, 0 };
    wa_pbf_t f;
    int rc;
    memset(out, 0, sizeof(*out));
    while ((rc = wa_pbr_next(&r, &f)) == 1) {
        int ok;
        if (f.wire != WA_PB_LEN)
            continue;
        if (f.field == 1)
            ok = decode_noise_cert(f.data, f.datalen, &out->leaf_details,
                                   &out->leaf_details_len, &out->leaf_sig,
                                   &out->leaf_sig_len);
        else if (f.field == 2)
            ok = decode_noise_cert(f.data, f.datalen, &out->int_details,
                                   &out->int_details_len, &out->int_sig,
                                   &out->int_sig_len);
        else
            continue;
        if (ok) {
            wa_certchain_free(out);
            return -1;
        }
    }
    if (rc < 0 || !out->leaf_details || !out->leaf_sig || !out->int_details ||
        !out->int_sig) {
        wa_certchain_free(out);
        return -1;
    }
    return 0;
}

int wa_pb_decode_cert_details(const uint8_t *msg, size_t len,
                              uint32_t *serial, uint32_t *issuer,
                              const uint8_t **key, size_t *keylen) {
    wa_pbr_t r = { msg, len, 0 };
    wa_pbf_t f;
    int rc, have_key = 0;
    *serial = *issuer = 0;
    *key = NULL;
    *keylen = 0;
    while ((rc = wa_pbr_next(&r, &f)) == 1) {
        if (f.field == 1 && f.wire == WA_PB_VARINT)
            *serial = (uint32_t)f.varint;
        else if (f.field == 2 && f.wire == WA_PB_VARINT)
            *issuer = (uint32_t)f.varint;
        else if (f.field == 3 && f.wire == WA_PB_LEN) {
            *key = f.data;
            *keylen = f.datalen;
            have_key = 1;
        }
    }
    if (rc < 0 || !have_key)
        return -1;
    return 0;
}

/* ---------------- ClientPayload ---------------- */

static int app_version(wa_pbw_t *out, uint32_t p, uint32_t s, uint32_t t) {
    wa_pbw_t v;
    wa_pbw_init(&v);
    if (wa_pbw_u32(&v, 1, p) || wa_pbw_u32(&v, 2, s) || wa_pbw_u32(&v, 3, t) ||
        wa_pbw_msg(out, 2, &v)) {
        wa_pbw_free(&v);
        return -1;
    }
    wa_pbw_free(&v);
    return 0;
}

/* UserAgent{platform:WEB, appVersion 2.3000.1043857760, mcc/mnc 000,
 * osVersion 0.1, device Desktop, osBuildNumber 0.1, RELEASE, en, US} */
static int user_agent(wa_pbw_t *out) {
    wa_pbw_t ua;
    wa_pbw_init(&ua);
    if (wa_pbw_u32(&ua, 1, 14) || /* Platform.WEB */
        app_version(&ua, 2, 3000, 1043857760) || wa_pbw_str(&ua, 3, "000") ||
        wa_pbw_str(&ua, 4, "000") || wa_pbw_str(&ua, 5, "0.1") ||
        wa_pbw_str(&ua, 7, "Desktop") || wa_pbw_str(&ua, 8, "0.1") ||
        wa_pbw_u32(&ua, 10, 0) || /* ReleaseChannel.RELEASE */
        wa_pbw_str(&ua, 11, "en") || wa_pbw_str(&ua, 12, "US") ||
        wa_pbw_msg(out, 5, &ua)) {
        wa_pbw_free(&ua);
        return -1;
    }
    wa_pbw_free(&ua);
    return 0;
}

/* WebInfo{webSubPlatform: WEB_BROWSER} */
static int web_info(wa_pbw_t *out) {
    wa_pbw_t w;
    wa_pbw_init(&w);
    if (wa_pbw_u32(&w, 4, 0) || wa_pbw_msg(out, 6, &w)) {
        wa_pbw_free(&w);
        return -1;
    }
    wa_pbw_free(&w);
    return 0;
}

/* HistorySyncConfig with Baileys' exact field set. */
static int history_sync_config(wa_pbw_t *out) {
    wa_pbw_t h;
    wa_pbw_init(&h);
    if (wa_pbw_u32(&h, 3, 10240) || wa_pbw_bool(&h, 4, 1) ||
        wa_pbw_bool(&h, 6, 0) || wa_pbw_bool(&h, 7, 1) ||
        wa_pbw_bool(&h, 8, 1) || wa_pbw_bool(&h, 9, 1) ||
        wa_pbw_bool(&h, 10, 1) || wa_pbw_bool(&h, 11, 1) ||
        wa_pbw_bool(&h, 12, 1) || wa_pbw_bool(&h, 14, 1) ||
        wa_pbw_bool(&h, 15, 0) || wa_pbw_msg(out, 5, &h)) {
        wa_pbw_free(&h);
        return -1;
    }
    wa_pbw_free(&h);
    return 0;
}

/* DeviceProps{os, version 10.15.7, platformType, requireFullSync, hsc} */
static int device_props(wa_pbw_t *out, const char *os, uint32_t platform) {
    wa_pbw_t d, v;
    wa_pbw_init(&d);
    wa_pbw_init(&v);
    if (wa_pbw_str(&d, 1, os) || wa_pbw_u32(&v, 1, 10) ||
        wa_pbw_u32(&v, 2, 15) || wa_pbw_u32(&v, 3, 7) ||
        wa_pbw_msg(&d, 2, &v) || wa_pbw_u32(&d, 3, platform) ||
        wa_pbw_bool(&d, 4, 1) || history_sync_config(&d)) {
        wa_pbw_free(&v);
        wa_pbw_free(&d);
        return -1;
    }
    wa_pbw_free(&v);
    if (wa_pbw_msg(out, 8, &d)) {
        wa_pbw_free(&d);
        return -1;
    }
    wa_pbw_free(&d);
    return 0;
}

static void be_encode(uint32_t v, int nbytes, uint8_t *out) {
    for (int i = nbytes - 1; i >= 0; i--) {
        out[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
}

int wa_pb_encode_registration(const uint8_t ident_pub[32],
                              const uint8_t pre_pub[32],
                              const uint8_t pre_sig[64], uint32_t pre_id,
                              uint32_t registration_id, const char *push_name,
                              wa_pbw_t *out) {
    uint8_t md5[16], eregid[4], eskeyid[3];
    static const uint8_t keytype = 5;
    wa_pbw_t p, dp;
    unsigned md5len = 0;
    be_encode(registration_id, 4, eregid);
    be_encode(pre_id, 3, eskeyid);
    if (!EVP_Digest(WA_APP_VERSION_STR, sizeof(WA_APP_VERSION_STR) - 1, md5,
                    &md5len, EVP_md5(), NULL) ||
        md5len != 16)
        return -1;
    wa_pbw_init(&p);
    wa_pbw_init(out);
    /* base payload */
    if (wa_pbw_bool(&p, 3, 0) || user_agent(&p) || web_info(&p) ||
        (push_name && *push_name ? wa_pbw_str(&p, 7, push_name) : 0) ||
        wa_pbw_u32(&p, 12, 1) || /* ConnectType.WIFI_UNKNOWN */
        wa_pbw_u32(&p, 13, 1) || /* ConnectReason.USER_ACTIVATED */
        wa_pbw_bool(&p, 33, 0)) /* pull=false */
        goto fail;
    /* devicePairingData */
    wa_pbw_init(&dp);
    if (wa_pbw_bytes(&dp, 1, eregid, 4) ||
        wa_pbw_bytes(&dp, 2, &keytype, 1) ||
        wa_pbw_bytes(&dp, 3, ident_pub, 32) ||
        wa_pbw_bytes(&dp, 4, eskeyid, 3) ||
        wa_pbw_bytes(&dp, 5, pre_pub, 32) ||
        wa_pbw_bytes(&dp, 6, pre_sig, 64) ||
        wa_pbw_bytes(&dp, 7, md5, 16) ||
        device_props(&dp, "Mac OS", 1) || /* PlatformType.CHROME */
        wa_pbw_msg(&p, 19, &dp)) {
        wa_pbw_free(&dp);
        goto fail;
    }
    wa_pbw_free(&dp);
    if (wa_pbw_raw(out, p.data, p.len)) {
        wa_pbw_free(&p);
        wa_pbw_free(out);
        return -1;
    }
    wa_pbw_free(&p);
    return 0;
fail:
    wa_pbw_free(&p);
    wa_pbw_free(out);
    return -1;
}

int wa_pb_encode_login(uint64_t username, int have_device, uint32_t device,
                       const char *push_name, wa_pbw_t *out) {
    wa_pbw_t p;
    wa_pbw_init(&p);
    wa_pbw_init(out);
    if (wa_pbw_u64(&p, 1, username) || wa_pbw_bool(&p, 3, 1) ||
        user_agent(&p) || web_info(&p) ||
        (push_name && *push_name ? wa_pbw_str(&p, 7, push_name) : 0) ||
        wa_pbw_u32(&p, 12, 1) || wa_pbw_u32(&p, 13, 1) ||
        (have_device ? wa_pbw_u32(&p, 18, device) : 0) ||
        wa_pbw_bool(&p, 33, 1) || wa_pbw_bool(&p, 41, 0) ||
        wa_pbw_raw(out, p.data, p.len)) {
        wa_pbw_free(&p);
        wa_pbw_free(out);
        return -1;
    }
    wa_pbw_free(&p);
    return 0;
}

/* ---------------- ADV identities ---------------- */

int wa_pb_decode_adv_hmac(const uint8_t *msg, size_t len,
                          const uint8_t **details, size_t *details_len,
                          uint8_t hmac[32], int *account_type) {
    wa_pbr_t r = { msg, len, 0 };
    wa_pbf_t f;
    int rc, have_d = 0, have_h = 0;
    *details = NULL;
    *details_len = 0;
    *account_type = WA_ADV_E2EE;
    while ((rc = wa_pbr_next(&r, &f)) == 1) {
        if (f.field == 1 && f.wire == WA_PB_LEN) {
            *details = f.data;
            *details_len = f.datalen;
            have_d = 1;
        } else if (f.field == 2 && f.wire == WA_PB_LEN && f.datalen == 32) {
            memcpy(hmac, f.data, 32);
            have_h = 1;
        } else if (f.field == 3 && f.wire == WA_PB_VARINT) {
            *account_type = (int)f.varint;
        }
    }
    return (rc == 0 && have_d && have_h) ? 0 : -1;
}

int wa_pb_decode_adv_account(const uint8_t *msg, size_t len,
                             const uint8_t **details, size_t *details_len,
                             const uint8_t **sigkey, size_t *sigkey_len,
                             const uint8_t **sig, size_t *sig_len,
                             const uint8_t **devsig, size_t *devsig_len) {
    wa_pbr_t r = { msg, len, 0 };
    wa_pbf_t f;
    int rc, have_d = 0, have_s = 0;
    *details = *sigkey = *sig = *devsig = NULL;
    *details_len = *sigkey_len = *sig_len = *devsig_len = 0;
    while ((rc = wa_pbr_next(&r, &f)) == 1) {
        if (f.wire != WA_PB_LEN)
            continue;
        if (f.field == 1) {
            *details = f.data;
            *details_len = f.datalen;
            have_d = 1;
        } else if (f.field == 2) {
            *sigkey = f.data;
            *sigkey_len = f.datalen;
        } else if (f.field == 3) {
            *sig = f.data;
            *sig_len = f.datalen;
            have_s = 1;
        } else if (f.field == 4) {
            *devsig = f.data;
            *devsig_len = f.datalen;
        }
    }
    return (rc == 0 && have_d && have_s) ? 0 : -1;
}

int wa_pb_decode_adv_device(const uint8_t *msg, size_t len,
                            uint32_t *key_index, int *device_type) {
    wa_pbr_t r = { msg, len, 0 };
    wa_pbf_t f;
    int rc, have_k = 0;
    *key_index = 0;
    *device_type = WA_ADV_E2EE;
    while ((rc = wa_pbr_next(&r, &f)) == 1) {
        if (f.field == 3 && f.wire == WA_PB_VARINT) {
            *key_index = (uint32_t)f.varint;
            have_k = 1;
        } else if (f.field == 5 && f.wire == WA_PB_VARINT) {
            *device_type = (int)f.varint;
        }
    }
    return (rc == 0 && have_k) ? 0 : -1;
}

int wa_pb_encode_adv_device(uint32_t key_index, int device_type,
                            wa_pbw_t *out) {
    wa_pbw_init(out);
    if (wa_pbw_u32(out, 3, key_index) || wa_pbw_u32(out, 5, (uint32_t)device_type)) {
        wa_pbw_free(out);
        return -1;
    }
    return 0;
}

int wa_pb_encode_adv_account(const uint8_t *details, size_t details_len,
                             const uint8_t *sigkey, size_t sigkey_len,
                             const uint8_t *sig, size_t sig_len,
                             const uint8_t *devsig, size_t devsig_len,
                             wa_pbw_t *out) {
    wa_pbw_init(out);
    if (wa_pbw_bytes(out, 1, details, details_len) ||
        (sigkey && sigkey_len ? wa_pbw_bytes(out, 2, sigkey, sigkey_len) : 0) ||
        wa_pbw_bytes(out, 3, sig, sig_len) ||
        (devsig && devsig_len ? wa_pbw_bytes(out, 4, devsig, devsig_len) : 0)) {
        wa_pbw_free(out);
        return -1;
    }
    return 0;
}

int wa_pb_encode_adv_hmac(const uint8_t *details, size_t details_len,
                           const uint8_t hmac[32], int have_type,
                           int account_type, wa_pbw_t *out) {
    wa_pbw_init(out);
    if (wa_pbw_bytes(out, 1, details, details_len) ||
        wa_pbw_bytes(out, 2, hmac, 32) ||
        (have_type ? wa_pbw_u32(out, 3, (uint32_t)account_type) : 0)) {
        wa_pbw_free(out);
        return -1;
    }
    return 0;
}

/* Message{conversation=1} — mirrors proto.Message{conversation} for text. */
int wa_pb_encode_wamessage_text(const char *text, wa_pbw_t *out) {
    wa_pbw_init(out);
    if (!text)
        return -1;
    if (wa_pbw_str(out, 1, text)) {
        wa_pbw_free(out);
        return -1;
    }
    return 0;
}

/* WhisperMessage{ephemeralKey=1,counter=2,previousCounter=3,ciphertext=4}. */
int wa_pb_encode_whisper(const uint8_t *eph_33, uint32_t counter,
                         uint32_t prev_counter, const uint8_t *ct,
                         size_t ct_len, wa_pbw_t *out) {
    wa_pbw_init(out);
    if (!eph_33 || !ct)
        return -1;
    if (wa_pbw_bytes(out, 1, eph_33, 33) || wa_pbw_u32(out, 2, counter) ||
        wa_pbw_u32(out, 3, prev_counter) ||
        wa_pbw_bytes(out, 4, ct, ct_len)) {
        wa_pbw_free(out);
        return -1;
    }
    return 0;
}

/* PreKeyWhisperMessage{preKeyId=1,baseKey=2,identityKey=3,message=4,
 * registrationId=5,signedPreKeyId=6}. */
int wa_pb_decode_prekey_msg(const uint8_t *msg, size_t len,
                            wa_pb_prekey_t *out) {
    wa_pbr_t r;
    wa_pbf_t f;
    int rc;
    if (!msg || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    r.p = msg;
    r.len = len;
    r.pos = 0;
    while ((rc = wa_pbr_next(&r, &f)) == 1) {
        switch (f.field) {
        case 1:
            out->prekey_id = (uint32_t)f.varint;
            out->has_prekey_id = 1;
            break;
        case 2:
            out->base_key = f.data;
            out->base_key_len = f.datalen;
            break;
        case 3:
            out->identity_key = f.data;
            out->identity_key_len = f.datalen;
            break;
        case 4:
            out->message = f.data;
            out->message_len = f.datalen;
            break;
        case 5:
            out->registration_id = (uint32_t)f.varint;
            out->has_registration_id = 1;
            break;
        case 6:
            out->signed_prekey_id = (uint32_t)f.varint;
            out->has_signed_prekey_id = 1;
            break;
        default:
            break;
        }
    }
    if (rc < 0)
        return -1;
    if (!out->base_key || !out->identity_key || !out->message)
        return -1;
    return 0;
}

int wa_pb_decode_whisper(const uint8_t *msg, size_t len, wa_pb_whisper_t *out) {
    wa_pbr_t r;
    wa_pbf_t f;
    int rc;
    if (!msg || !out)
        return -1;
    memset(out, 0, sizeof(*out));
    r.p = msg;
    r.len = len;
    r.pos = 0;
    while ((rc = wa_pbr_next(&r, &f)) == 1) {
        switch (f.field) {
        case 1:
            out->ephemeral_key = f.data;
            out->ephemeral_key_len = f.datalen;
            break;
        case 2:
            out->counter = (uint32_t)f.varint;
            out->has_counter = 1;
            break;
        case 3:
            out->previous_counter = (uint32_t)f.varint;
            out->has_previous_counter = 1;
            break;
        case 4:
            out->ciphertext = f.data;
            out->ciphertext_len = f.datalen;
            break;
        default:
            break;
        }
    }
    if (rc < 0)
        return -1;
    if (!out->ephemeral_key || !out->ciphertext)
        return -1;
    return 0;
}

static int copy_text(const uint8_t *data, size_t len, char *out, size_t outcap) {
    size_t n = len < outcap - 1 ? len : outcap - 1;
    if (!outcap)
        return -1;
    memcpy(out, data, n);
    out[n] = '\0';
    return 0;
}

int wa_pb_decode_wamessage_text(const uint8_t *msg, size_t len, char *out,
                                size_t outcap) {
    wa_pbr_t r;
    wa_pbf_t f;
    int rc;
    const uint8_t *dev_msg = NULL;
    size_t dev_len = 0;
    if (!msg || !out || !outcap)
        return -1;
    out[0] = '\0';
    r.p = msg;
    r.len = len;
    r.pos = 0;
    while ((rc = wa_pbr_next(&r, &f)) == 1) {
        if (f.field == 1 && f.wire == WA_PB_LEN) { /* conversation */
            return copy_text(f.data, f.datalen, out, outcap);
        }
        if (f.field == 6 && f.wire == WA_PB_LEN) { /* extendedTextMessage */
            wa_pbr_t e;
            wa_pbf_t g;
            int grc;
            e.p = f.data;
            e.len = f.datalen;
            e.pos = 0;
            while ((grc = wa_pbr_next(&e, &g)) == 1) {
                if (g.field == 1 && g.wire == WA_PB_LEN) /* text */
                    return copy_text(g.data, g.datalen, out, outcap);
            }
        }
        if (f.field == 31 && f.wire == WA_PB_LEN) { /* deviceSentMessage */
            wa_pbr_t d;
            wa_pbf_t g;
            int drc;
            d.p = f.data;
            d.len = f.datalen;
            d.pos = 0;
            while ((drc = wa_pbr_next(&d, &g)) == 1) {
                if (g.field == 2 && g.wire == WA_PB_LEN) { /* message */
                    dev_msg = g.data;
                    dev_len = g.datalen;
                }
            }
        }
    }
    if (rc < 0)
        return -1;
    if (dev_msg)
        return wa_pb_decode_wamessage_text(dev_msg, dev_len, out, outcap);
    return -1;
}

/* PreKeyWhisperMessage{preKeyId=1,baseKey=2,identityKey=3,message=4,
 * registrationId=5,signedPreKeyId=6}. */
int wa_pb_encode_prekey_msg(const uint8_t *identity_33,
                            const uint8_t *base_33,
                            uint32_t registration_id, uint32_t signed_prekey_id,
                            int have_prekey_id, uint32_t prekey_id,
                            const uint8_t *inner, size_t inner_len,
                            wa_pbw_t *out) {
    wa_pbw_init(out);
    if (!identity_33 || !base_33 || !inner)
        return -1;
    if ((have_prekey_id ? wa_pbw_u32(out, 1, prekey_id) : 0) ||
        wa_pbw_bytes(out, 2, base_33, 33) ||
        wa_pbw_bytes(out, 3, identity_33, 33) ||
        wa_pbw_bytes(out, 4, inner, inner_len) ||
        wa_pbw_u32(out, 5, registration_id) ||
        wa_pbw_u32(out, 6, signed_prekey_id)) {
        wa_pbw_free(out);
        return -1;
    }
    return 0;
}


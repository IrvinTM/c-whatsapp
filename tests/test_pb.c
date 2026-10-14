/* test_pb.c — protobuf codec vs Baileys vectors.
 *
 * Encode vectors cross-checked with Baileys protobufjs (WAProto field
 * numbers are WhatsApp-stable); registration structure additionally
 * verified by decoding our output with Baileys' own decoder.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa_auth.h"
#include "wa_crypto.h"
#include "wa_pairing.h"
#include "wa_pb.h"

static size_t unhex(const char *h, uint8_t *out, size_t olen) {
    size_t n = strlen(h) / 2;
    assert(strlen(h) % 2 == 0 && n <= olen);
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        assert(sscanf(h + 2 * i, "%2x", &v) == 1);
        out[i] = (uint8_t)v;
    }
    return n;
}

static void expect_hex(const char *name, const uint8_t *got, size_t glen,
                       const char *want_hex) {
    /* want_hex may be long; compare in chunks to keep literals readable. */
    size_t wlen = strlen(want_hex) / 2;
    uint8_t *want = malloc(wlen);
    assert(want);
    assert(unhex(want_hex, want, wlen) == wlen);
    if (glen != wlen || memcmp(got, want, wlen) != 0) {
        printf("MISMATCH [%s]: got %zu bytes, want %zu bytes\n", name, glen,
               wlen);
        printf("got:  ");
        for (size_t i = 0; i < glen; i++)
            printf("%02x", got[i]);
        printf("\n");
        free(want);
        assert(0);
    }
    free(want);
    printf("ok: %s (%zu bytes)\n", name, glen);
}

static void t_hello(void) {
    uint8_t eph[32];
    wa_pbw_t out;
    for (int i = 0; i < 32; i++)
        eph[i] = (uint8_t)(i + 1);
    assert(wa_pb_encode_client_hello(eph, &out) == 0);
    expect_hex("client-hello", out.data, out.len,
               "12220a200102030405060708090a0b0c0d0e0f101112131415161718191a"
               "1b1c1d1e1f20");
    wa_pbw_free(&out);
}

static void t_finish(void) {
    uint8_t st[48], pay[16];
    wa_pbw_t out;
    memset(st, 5, sizeof(st));
    memset(pay, 6, sizeof(pay));
    assert(wa_pb_encode_client_finish(st, sizeof(st), pay, sizeof(pay), &out) == 0);
    expect_hex("client-finish", out.data, out.len,
               "22440a3005050505050505050505050505050505050505050505050505050505"
               "0505050505050505050505050505050505050505121006060606060606060606"
               "060606060606");
    wa_pbw_free(&out);
}

static void t_login(void) {
    wa_pbw_t out;
    assert(wa_pb_encode_login(15551234567ull, 0, 0, NULL, &out) == 0);
    expect_hex("login", out.data, out.len,
               "088784b4f73918012a36080e120b080210b81718e082e0f1031a033030302"
               "2033030302a03302e313a074465736b746f704203302e3150005a02656e"
               "620255533202200060016801880201c80200");
    wa_pbw_free(&out);
    /* with device + push name */
    assert(wa_pb_encode_login(15551234567ull, 1, 5, "bob", &out) == 0);
    {
        /* spot-check: device field 18 varint 5, pushName field 7 "bob" */
        int has_dev = 0, has_name = 0;
        wa_pbr_t r = { out.data, out.len, 0 };
        wa_pbf_t f;
        int rc;
        while ((rc = wa_pbr_next(&r, &f)) == 1) {
            if (f.field == 18 && f.wire == WA_PB_VARINT && f.varint == 5)
                has_dev = 1;
            if (f.field == 7 && f.wire == WA_PB_LEN && f.datalen == 3 &&
                !memcmp(f.data, "bob", 3))
                has_name = 1;
        }
        assert(rc == 0 && has_dev && has_name);
    }
    wa_pbw_free(&out);
    printf("ok: login-device-pushname\n");
}

/* Walk dotted field path (e.g. {19,8,2}) to a nested message slice. */
static int find_msg(const uint8_t *d, size_t n, const uint32_t *path, int depth,
                    const uint8_t **out, size_t *outlen) {
    wa_pbr_t r = { d, n, 0 };
    wa_pbf_t f;
    int rc;
    while ((rc = wa_pbr_next(&r, &f)) == 1) {
        if (f.field == path[0] && f.wire == WA_PB_LEN) {
            if (depth == 1) {
                *out = f.data;
                *outlen = f.datalen;
                return 0;
            }
            return find_msg(f.data, f.datalen, path + 1, depth - 1, out,
                            outlen);
        }
    }
    return -1;
}

static uint64_t find_varint(const uint8_t *d, size_t n, uint32_t field,
                            int *found) {
    wa_pbr_t r = { d, n, 0 };
    wa_pbf_t f;
    int rc;
    while ((rc = wa_pbr_next(&r, &f)) == 1)
        if (f.field == field && f.wire == WA_PB_VARINT) {
            *found = 1;
            return f.varint;
        }
    *found = 0;
    return 0;
}

static void t_registration(void) {
    uint8_t ident[32], pre[32], sig[64];
    wa_pbw_t out;
    const uint8_t *dp, *props, *hsc;
    size_t dplen, propslen, hsclen;
    int found;
    memset(ident, 0x11, sizeof(ident));
    memset(pre, 0x22, sizeof(pre));
    memset(sig, 0x33, sizeof(sig));
    assert(wa_pb_encode_registration(ident, pre, sig, 1, 1234, NULL, &out) == 0);
    /* top-level flags */
    assert(find_varint(out.data, out.len, 3, &found) == 0 && found); /* passive=false */
    assert(find_varint(out.data, out.len, 33, &found) == 0 && found); /* pull=false */
    /* devicePairingData */
    {
        static const uint32_t path[] = { 19 };
        assert(find_msg(out.data, out.len, path, 1, &dp, &dplen) == 0);
    }
    {
        wa_pbr_t r = { dp, dplen, 0 };
        wa_pbf_t f;
        int rc, seen[8] = { 0 };
        while ((rc = wa_pbr_next(&r, &f)) == 1) {
            if (f.field >= 1 && f.field <= 8 && f.wire == WA_PB_LEN)
                seen[f.field - 1] = (int)f.datalen;
        }
        assert(rc == 0);
        for (int i = 0; i < 8; i++)
            assert(seen[i] > 0);
        assert(seen[0] == 4 && seen[1] == 1 && seen[2] == 32 &&
               seen[3] == 3 && seen[4] == 32 && seen[5] == 64 &&
               seen[6] == 16);
    }
    /* deviceProps.version = 10.15.7, platformType=1, fullSync, hsc */
    {
        static const uint32_t path[] = { 19, 8 };
        assert(find_msg(out.data, out.len, path, 2, &props, &propslen) == 0);
        assert(find_varint(props, propslen, 3, &found) == 1 && found);
        assert(find_varint(props, propslen, 4, &found) == 1 && found);
    }
    {
        static const uint32_t vpath[] = { 19, 8, 2 };
        const uint8_t *v;
        size_t vlen;
        assert(find_msg(out.data, out.len, vpath, 3, &v, &vlen) == 0);
        assert(find_varint(v, vlen, 1, &found) == 10 && found);
        assert(find_varint(v, vlen, 2, &found) == 15 && found);
        assert(find_varint(v, vlen, 3, &found) == 7 && found);
    }
    {
        static const uint32_t hpath[] = { 19, 8, 5 };
        assert(find_msg(out.data, out.len, hpath, 3, &hsc, &hsclen) == 0);
        assert(find_varint(hsc, hsclen, 3, &found) == 10240 && found);
        assert(find_varint(hsc, hsclen, 4, &found) == 1 && found);
        assert(find_varint(hsc, hsclen, 15, &found) == 0 && found);
    }
    printf("ok: registration-structure (%zu bytes)\n", out.len);
    wa_pbw_free(&out);
}

static void t_serverhello_decode(void) {
    uint8_t raw[256];
    size_t n = unhex(
        "1a96010a20070707070707070707070707070707070707070707070707070707"
        "0707070707123008080808080808080808080808080808080808080808080808"
        "08080808080808080808080808080808080808080808081a4009090909090909"
        "0909090909090909090909090909090909090909090909090909090909090909"
        "09090909090909090909090909090909090909090909090909",
        raw, sizeof(raw));
    uint8_t eph[32], *stat = NULL, *pay = NULL;
    size_t statlen = 0, paylen = 0;
    assert(wa_pb_decode_server_hello(raw, n, eph, &stat, &statlen, &pay,
                                     &paylen) == 0);
    for (int i = 0; i < 32; i++)
        assert(eph[i] == 7);
    assert(statlen == 48 && stat[0] == 8);
    assert(paylen == 64 && pay[0] == 9);
    free(stat);
    free(pay);
    printf("ok: serverhello-decode\n");
}

static void t_certchain_decode(void) {
    uint8_t raw[256];
    size_t n = unhex(
        "0a4f0a0b4c45414644455441494c531240010101010101010101010101010101"
        "0101010101010101010101010101010101010101010101010101010101010101"
        "0101010101010101010101010101010101124e0a0a494e5444455441494c5312"
        "4002020202020202020202020202020202020202020202020202020202020202"
        "0202020202020202020202020202020202020202020202020202020202020202"
        "02",
        raw, sizeof(raw));
    wa_certchain_t c;
    assert(wa_pb_decode_cert_chain(raw, n, &c) == 0);
    assert(c.leaf_details_len == 11 &&
           !memcmp(c.leaf_details, "LEAFDETAILS", 11));
    assert(c.leaf_sig_len == 64 && c.leaf_sig[0] == 1);
    assert(c.int_details_len == 10 && !memcmp(c.int_details, "INTDETAILS", 10));
    assert(c.int_sig_len == 64 && c.int_sig[0] == 2);
    wa_certchain_free(&c);
    printf("ok: certchain-decode\n");
}

static void t_pair_success(void);

int main(void) {
    t_hello();
    t_finish();
    t_login();
    t_registration();
    t_serverhello_decode();
    t_certchain_decode();
    t_pair_success();
    printf("all pb tests passed\n");
    return 0;
}

/* Synthetic pair-success: build the phone side with fixed keys, verify our
 * handler replies correctly (structure + device signature). */
static void t_pair_success(void) {
    uint8_t adv[32], ident_priv[32], ident_pub[32];
    uint8_t acc_priv[32], acc_pub[32];
    wa_pbw_t dev_enc, acc_enc, hmac_enc;
    wa_creds_t creds;
    wa_node_t *stanza, *ps, *di_node, *plat, *dev, *reply;
    int i;
    for (i = 0; i < 32; i++) {
        adv[i] = (uint8_t)(i + 1);
        ident_priv[i] = (uint8_t)(0xa0 + i);
        acc_priv[i] = (uint8_t)(0x50 + i);
    }
    assert(wa_x25519_pub(ident_pub, ident_priv) == 0);
    assert(wa_x25519_pub(acc_pub, acc_priv) == 0);

    /* deviceDetails = ADVDeviceIdentity{keyIndex 7} */
    assert(wa_pb_encode_adv_device(7, WA_ADV_E2EE, &dev_enc) == 0);
    /* accountSig = sign(acc_priv, [6,0] + details + ident_pub) */
    {
        uint8_t msg[2 + 256 + 32];
        uint8_t asig[64];
        size_t need = 2 + dev_enc.len + 32;
        assert(need <= sizeof(msg));
        msg[0] = 6;
        msg[1] = 0;
        memcpy(msg + 2, dev_enc.data, dev_enc.len);
        memcpy(msg + 2 + dev_enc.len, ident_pub, 32);
        assert(wa_xeddsa_sign(acc_priv, msg, need, asig) == 0);
        assert(wa_pb_encode_adv_account(dev_enc.data, dev_enc.len, acc_pub,
                                        32, asig, 64, NULL, 0, &acc_enc) == 0);
    }
    /* hmac = HMAC-SHA256(accountEnc, adv) (E2EE: empty prefix) */
    {
        uint8_t h[32];
        assert(wa_hmac_sha256(adv, 32, acc_enc.data, acc_enc.len, h) == 0);
        assert(wa_pb_encode_adv_hmac(acc_enc.data, acc_enc.len, h, 0, 0,
                                     &hmac_enc) == 0);
    }
    /* stanza */
    stanza = wa_node_new("iq");
    ps = wa_node_new("pair-success");
    di_node = wa_node_new("device-identity");
    plat = wa_node_new("platform");
    dev = wa_node_new("device");
    assert(stanza && ps && di_node && plat && dev);
    assert(wa_node_add_attr(stanza, "id", "pair.1") == 0);
    assert(wa_node_add_attr(stanza, "type", "set") == 0);
    assert(wa_node_set_bytes(di_node, hmac_enc.data, hmac_enc.len) == 0);
    assert(wa_node_add_attr(plat, "name", "TestOS") == 0);
    assert(wa_node_add_attr(dev, "jid", "1@s.whatsapp.net") == 0);
    assert(wa_node_add_attr(dev, "lid", "2@lid") == 0);
    assert(wa_node_add_child(ps, di_node) == 0);
    assert(wa_node_add_child(ps, plat) == 0);
    assert(wa_node_add_child(ps, dev) == 0);
    assert(wa_node_add_child(stanza, ps) == 0);

    wa_creds_init(&creds);
    memcpy(creds.ident_priv, ident_priv, 32);
    memcpy(creds.ident_pub, ident_pub, 32);
    memcpy(creds.adv_secret, adv, 32);
    assert(wa_pair_success(&creds, stanza, &reply) == 0);
    assert(reply);

    /* reply: iq result pair.1 -> pair-device-sign -> device-identity */
    assert(!strcmp(wa_node_get_attr(reply, "type"), "result"));
    assert(!strcmp(wa_node_get_attr(reply, "id"), "pair.1"));
    {
        wa_node_t *pds = wa_node_get_child(reply, "pair-device-sign");
        wa_node_t *di = wa_node_get_child(pds, "device-identity");
        const uint8_t *d, *k, *s, *ds;
        size_t dl, kl, sl, dsl;
        assert(pds && di);
        assert(!strcmp(wa_node_get_attr(di, "key-index"), "7"));
        assert(di->ctype == WA_CONTENT_BYTES);
        assert(wa_pb_decode_adv_account(di->content.bytes.data,
                                        di->content.bytes.len, &d, &dl, &k,
                                        &kl, &s, &sl, &ds, &dsl) == 0);
        assert(k == NULL && kl == 0); /* signature key omitted */
        assert(sl == 64 && dsl == 64 && dl == dev_enc.len);
        /* our device signature verifies under ident_pub */
        {
            uint8_t msg[2 + 256 + 32 + 32];
            size_t need = 2 + dl + 32 + 32;
            assert(need <= sizeof(msg));
            msg[0] = 6;
            msg[1] = 1;
            memcpy(msg + 2, d, dl);
            memcpy(msg + 2 + dl, ident_pub, 32);
            memcpy(msg + 2 + dl + 32, acc_pub, 32);
            assert(wa_xeddsa_verify(ident_pub, msg, need, ds) == 0);
        }
    }
    /* creds updated */
    assert(!strcmp(creds.me_id, "1@s.whatsapp.net"));
    assert(!strcmp(creds.me_lid, "2@lid"));
    assert(!strcmp(creds.platform, "TestOS"));
    assert(creds.account.present && creds.account.key_index == 7);

    /* tampered HMAC must fail */
    hmac_enc.data[hmac_enc.len - 1] ^= 1;
    assert(wa_node_set_bytes(di_node, hmac_enc.data, hmac_enc.len) == 0);
    {
        wa_node_t *bad = NULL;
        assert(wa_pair_success(&creds, stanza, &bad) != 0 && bad == NULL);
    }

    wa_node_free(reply);
    wa_node_free(stanza);
    wa_pbw_free(&dev_enc);
    wa_pbw_free(&acc_enc);
    wa_pbw_free(&hmac_enc);
    printf("ok: pair-success\n");
}

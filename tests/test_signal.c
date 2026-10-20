/* test_signal.c — Signal session round-trip (initiator <-> responder). */
#define _POSIX_C_SOURCE 200809L

#include "wa_auth.h"
#include "wa_crypto.h"
#include "wa_pb.h"
#include "wa_signal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fails = 0;
static void ok(int cond, const char *msg) {
    printf("%s: %s\n", cond ? "ok" : "FAIL", msg);
    if (!cond)
        fails++;
}

static int memeq(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

int main(void) {
    char tdir[] = "/tmp/cwa_sig_XXXXXX";
    char *dir = mkdtemp(tdir);
    wa_creds_t alice, bob;
    wa_sig_t as, bs, bs2;
    wa_bundle_t bundle;
    uint8_t opk_priv[32], opk_pub[32];
    uint8_t *body = NULL, *out = NULL;
    size_t blen = 0, outlen = 0;
    const char *m1 = "hello bob, this is alice";
    const char *m2 = "hi alice, bob here";
    const char *m3 = "second message on the ratchet";
    const char *m4 = "after a restart";

    if (!dir) {
        perror("mkdtemp");
        return 1;
    }
    memset(&alice, 0, sizeof(alice));
    memset(&bob, 0, sizeof(bob));
    if (wa_creds_generate(&alice) || wa_creds_generate(&bob)) {
        fprintf(stderr, "creds gen failed\n");
        return 1;
    }
    if (wa_x25519_pub(opk_pub, opk_priv)) {
        memset(opk_priv, 1, 32);
        wa_x25519_pub(opk_pub, opk_priv);
    }

    wa_sig_init(&as, dir, &alice);
    wa_sig_init(&bs, dir, &bob);
    wa_sig_add_opk(&bs, 7, opk_priv);

    memset(&bundle, 0, sizeof(bundle));
    memcpy(bundle.identity, bob.ident_pub, 32);
    memcpy(bundle.spk, bob.pre_pub, 32);
    bundle.spk_id = bob.pre_id;
    memcpy(bundle.spk_sig, bob.pre_sig, 64);
    memcpy(bundle.opk, opk_pub, 32);
    bundle.opk_id = 7;
    bundle.have_opk = 1;
    bundle.reg_id = bob.registration_id;

    /* Alice initiator -> Bob responder (pkmsg) */
    if (wa_sig_encrypt_pkmsg(&as, "bob:1@test", &bundle,
                             (const uint8_t *)m1, strlen(m1), &body, &blen)) {
        ok(0, "alice encrypt_pkmsg");
        return 1;
    }
    ok(blen > 0 && body[0] == 0x33, "pkmsg body framed");
    if (wa_sig_decrypt(&bs, "alice:1@test", "pkmsg", body, blen, &out,
                       &outlen)) {
        ok(0, "bob decrypt pkmsg");
    } else {
        ok(outlen == strlen(m1) && memeq(out, (const uint8_t *)m1, outlen),
           "pkmsg plaintext matches");
    }
    free(body);
    free(out);
    body = out = NULL;

    /* Bob -> Alice on the ratchet (msg) */
    if (wa_sig_encrypt(&bs, "alice:1@test", (const uint8_t *)m2, strlen(m2),
                       &body, &blen)) {
        ok(0, "bob encrypt msg");
    } else {
        ok(body[0] == 0x33, "msg body framed");
        if (wa_sig_decrypt(&as, "bob:1@test", "msg", body, blen, &out,
                           &outlen))
            ok(0, "alice decrypt msg");
        else
            ok(outlen == strlen(m2) && memeq(out, (const uint8_t *)m2, outlen),
               "ratchet reply matches");
    }
    free(body);
    free(out);
    body = out = NULL;

    /* Alice -> Bob second message on the same session */
    if (wa_sig_encrypt(&as, "bob:1@test", (const uint8_t *)m3, strlen(m3),
                       &body, &blen)) {
        ok(0, "alice encrypt msg 2");
    } else if (wa_sig_decrypt(&bs, "alice:1@test", "msg", body, blen, &out,
                              &outlen)) {
        ok(0, "bob decrypt msg 2");
    } else {
        ok(outlen == strlen(m3) && memeq(out, (const uint8_t *)m3, outlen),
           "second message matches");
    }
    free(body);
    free(out);
    body = out = NULL;

    /* persistence: reload Bob's store, decrypt a fresh Alice message */
    wa_sig_save(&bs);
    wa_sig_init(&bs2, dir, &bob);
    wa_sig_load(&bs2);
    ok(wa_sig_has_session(&bs2, "alice:1@test"), "reloaded session present");
    if (wa_sig_encrypt(&as, "bob:1@test", (const uint8_t *)m4, strlen(m4),
                       &body, &blen)) {
        ok(0, "alice encrypt msg 3");
    } else if (wa_sig_decrypt(&bs2, "alice:1@test", "msg", body, blen, &out,
                              &outlen)) {
        ok(0, "bob2 decrypt after reload");
    } else {
        ok(outlen == strlen(m4) && memeq(out, (const uint8_t *)m4, outlen),
           "post-reload message matches");
    }
    free(body);
    free(out);

    /* WAMessage text extraction */
    {
        uint8_t wm[64];
        /* field 1 (conversation), wire 2: tag=0x0A, len, bytes */
        const char *txt = "/reminder Mon-Fri 07:50 class";
        size_t tl = strlen(txt);
        char got[128];
        wm[0] = 0x0A;
        wm[1] = (uint8_t)tl;
        memcpy(wm + 2, txt, tl);
        ok(wa_pb_decode_wamessage_text(wm, tl + 2, got, sizeof(got)) == 0 &&
               !strcmp(got, txt),
           "wamessage conversation decode");
    }

    printf("%s\n", fails ? "some signal tests failed" : "all signal tests passed");
    return fails ? 1 : 0;
}

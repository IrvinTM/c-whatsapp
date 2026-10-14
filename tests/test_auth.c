/* test_auth.c — credential store roundtrips. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa_auth.h"

int main(void) {
    char dir[] = "/tmp/cwa-auth-test-XXXXXX";
    assert(mkdtemp(dir));

    /* fresh load -> "no session". */
    wa_creds_t c;
    assert(wa_auth_load(&c, dir) == 1);

    assert(wa_creds_generate(&c) == 0);
    snprintf(c.me_id, sizeof(c.me_id), "15551234567@s.whatsapp.net");
    snprintf(c.me_lid, sizeof(c.me_lid), "12345@lid");
    snprintf(c.me_name, sizeof(c.me_name), "test");
    c.registered = 1;
    c.routing_info_len = 4;
    c.routing_info[0] = 1;
    c.routing_info[1] = 2;
    c.routing_info[2] = 3;
    c.routing_info[3] = 4;
    assert(wa_auth_save(&c, dir) == 0);

    wa_creds_t back;
    assert(wa_auth_load(&back, dir) == 0);
    assert(memcmp(&c, &back, sizeof(c)) == 0);
    printf("ok: save/load roundtrip\n");

    /* base64 sanity vector: "Man" -> "TWFu". */
    char out[16];
    assert(wa_b64_encode((const uint8_t *)"Man", 3, out, sizeof(out)) == 0);
    assert(strcmp(out, "TWFu") == 0);
    uint8_t dec[8];
    size_t w = 0;
    assert(wa_b64_decode("TWFu", dec, sizeof(dec), &w) == 0);
    assert(w == 3 && memcmp(dec, "Man", 3) == 0);
    printf("ok: base64 vectors\n");

    /* corrupt file -> error, not crash. */
    char path[256];
    snprintf(path, sizeof(path), "%s/creds.json", dir);
    FILE *f = fopen(path, "w");
    assert(f);
    fputs("{ not json", f);
    fclose(f);
    wa_creds_t junk;
    assert(wa_auth_load(&junk, dir) == -1);
    printf("ok: corrupt file rejected\n");

    /* pre-Phase-5 session (no new keys) loads with sane defaults. */
    f = fopen(path, "w");
    assert(f);
    fputs("{", f);
    fputs("\"noise_priv\": \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",", f);
    fputs("\"noise_pub\": \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",", f);
    fputs("\"ident_priv\": \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",", f);
    fputs("\"ident_pub\": \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",", f);
    fputs("\"pre_priv\": \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",", f);
    fputs("\"pre_pub\": \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",", f);
    fputs("\"pre_sig\": \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\",", f);
    fputs("\"pre_id\": 1,", f);
    fputs("\"registration_id\": 42,", f);
    fputs("\"adv_secret\": \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",", f);
    fputs("\"routing_info\": \"\",", f);
    fputs("\"registered\": false,", f);
    fputs("\"me_id\": \"\",", f);
    fputs("\"me_lid\": \"\",", f);
    fputs("\"me_name\": \"\"", f);
    fputs("}", f);
    fclose(f);
    wa_creds_t old;
    assert(wa_auth_load(&old, dir) == 0);
    assert(old.registration_id == 42);
    assert(old.next_prekey_id == 1 && old.first_unuploaded_prekey_id == 1);
    assert(!old.account.present && !old.registered);
    printf("ok: old-session compat\n");

    printf("all auth tests passed\n");
    return 0;
}

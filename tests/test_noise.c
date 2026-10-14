/* test_noise.c — crypto primitives + Noise handler vs Baileys vectors.
 *
 * Fixed vectors were generated with node:crypto following Baileys
 * src/Utils/noise-handler.ts @74af8eee (init/auth/mix/encrypt order) and
 * RFC 5869 / RFC 7748 / RFC 8032. See tools/gen_tokens.py pin.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa_binary.h"
#include "wa_crypto.h"
#include "wa_noise.h"

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
    uint8_t want[256];
    size_t wlen = unhex(want_hex, want, sizeof(want));
    if (glen != wlen || memcmp(got, want, wlen) != 0) {
        printf("MISMATCH [%s]: got ", name);
        for (size_t i = 0; i < glen; i++)
            printf("%02x", got[i]);
        printf(" want %s\n", want_hex);
        assert(0);
    }
    printf("ok: %s\n", name);
}

static void t_sha256(void) {
    uint8_t d[32];
    wa_sha256((const uint8_t *)"abc", 3, d);
    expect_hex("sha256(abc)", d, 32,
               "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

static void t_hkdf(void) {
    uint8_t ikm[22], salt[13], info[10], okm[42];
    memset(ikm, 0x0b, sizeof(ikm));
    for (int i = 0; i < 13; i++)
        salt[i] = (uint8_t)i;
    for (int i = 0; i < 10; i++)
        info[i] = (uint8_t)(0xf0 + i);
    assert(wa_hkdf_sha256(okm, sizeof(okm), ikm, sizeof(ikm), salt,
                          sizeof(salt), info, sizeof(info)) == 0);
    expect_hex("hkdf-rfc5869-case1", okm, sizeof(okm),
               "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc"
               "4c5bf34007208d5b887185865");
}

static void t_gcm(void) {
    uint8_t key[32], iv[12], ct[64], pt[64];
    for (int i = 0; i < 32; i++)
        key[i] = (uint8_t)i;
    memset(iv, 0, sizeof(iv));
    iv[11] = 7;
    int cl = wa_aes_gcm_encrypt((const uint8_t *)"hello noise", 11, key, iv,
                                (const uint8_t *)"test-aad", 8, ct, sizeof(ct));
    assert(cl == 27);
    expect_hex("aes-gcm-vector", ct, (size_t)cl,
               "88087f7378373095ad2c8a3901b48aea911281f3dea954b3bda409");
    /* roundtrip + tamper rejection */
    int pl = wa_aes_gcm_decrypt(ct, (size_t)cl, key, iv,
                                (const uint8_t *)"test-aad", 8, pt, sizeof(pt));
    assert(pl == 11 && memcmp(pt, "hello noise", 11) == 0);
    ct[0] ^= 1;
    assert(wa_aes_gcm_decrypt(ct, (size_t)cl, key, iv,
                              (const uint8_t *)"test-aad", 8, pt,
                              sizeof(pt)) < 0);
    printf("ok: aes-gcm-roundtrip+tamper\n");
}

static void t_x25519(void) {
    uint8_t privA[32], pubA[32], privB[32], pubB[32], s1[32], s2[32];
    unhex("0104070a0d101316191c1f2225282b2e3134373a3d404346494c4f5255585b5e",
          privA, 32);
    unhex("050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7de",
          privB, 32);
    assert(wa_x25519_pub(pubA, privA) == 0);
    assert(wa_x25519_pub(pubB, privB) == 0);
    expect_hex("x25519-pubA", pubA, 32,
               "c37077fb432d19c51d6a8c6fdf9dbf06f8471cf12edb1cadab76aeac29917a1e");
    expect_hex("x25519-pubB", pubB, 32,
               "0ff8125a05ca7357c68e0b3f7ee6d330ae57a9f398c359af9c4c74aa54184b77");
    assert(wa_x25519_shared(s1, privA, pubB) == 0);
    assert(wa_x25519_shared(s2, privB, pubA) == 0);
    assert(memcmp(s1, s2, 32) == 0);
    expect_hex("x25519-shared", s1, 32,
               "a3d00cfa834f5875381b0bf37f359394dc95b2cc2a3a032994d912c751de1237");
}

static void t_ed25519(void) {
    uint8_t pub[32], sig[64];
    unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
          pub, 32);
    unhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
          "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
          sig, 64);
    /* RFC 8032 §7.1 TEST 1 (empty message). */
    assert(wa_ed25519_verify(pub, NULL, 0, sig) == 0);
    sig[0] ^= 1;
    assert(wa_ed25519_verify(pub, NULL, 0, sig) != 0);
    printf("ok: ed25519-rfc8032-t1\n");
}

static void t_xeddsa(void) {
    /* Real WhatsApp intermediate cert (captured live); libsignal
     * Curve.verify (XEdDSA) accepts it, raw Ed25519 does not. */
    uint8_t root[32], details[50], sig[64];
    unhex("142375574d0a587166aae71ebe516437c4a28b73e3695c6ce1f7f9545da8ee6b",
          root, 32);
    unhex("080310001a201c51a9ac303994c6c8d0b92ea1878a533476599cc599fbea35997"
          "d9aa90cce62208091aebe0628ffdeb7dc06",
          details, sizeof(details));
    unhex("270f294648539fed4870e25054dd4e95983aba29189c2ba6c8eeda7055555f75"
          "3740f5ec192ab64c26c26d6ade6d20b9f774aee37120a6b20395f53c66058507",
          sig, 64);
    assert(wa_ed25519_verify(root, details, sizeof(details), sig) != 0);
    assert(wa_xeddsa_verify(root, details, sizeof(details), sig) == 0);
    sig[0] ^= 1;
    assert(wa_xeddsa_verify(root, details, sizeof(details), sig) != 0);
    /* compiled-in root key must equal the verified value above */
    assert(memcmp(WA_CERT_PUBKEY, root, 32) == 0);
    printf("ok: xeddsa-live-cert\n");
}

static void t_xeddsa_sign(void) {
    /* libsignal calculateSignature vector (deterministic). */
    uint8_t priv[32], pub[32], sig[64];
    static const char *msg = "test-device-message";
    unhex("0714212e3b4855626f7c8996a3b0bdcad7e4f1fe0b1825323f4c596673808d9a",
          priv, 32);
    assert(wa_x25519_pub(pub, priv) == 0);
    expect_hex("xeddsa-pub", pub, 32,
               "7c6b7bdbb51b36f48a3c685efc8fd931d386b162d417da9a8364e43b4a14c528");
    assert(wa_xeddsa_sign(priv, (const uint8_t *)msg, strlen(msg), sig) == 0);
    expect_hex("xeddsa-sign", sig, 64,
               "d3bb3818ec8bacac02b34d1c7f809170830d120a4c68420cea3e6529b3d65"
               "3224ed2531d2370dcc55749e0ace413f09542ddd7dfb41379b0892c1e2e7c"
               "2c188a");
    assert(wa_xeddsa_verify(pub, (const uint8_t *)msg, strlen(msg), sig) == 0);
    printf("ok: xeddsa-sign-verify-roundtrip\n");
}

static void t_xeddsa_signbit(void) {
    /* libsignal vector whose signature carries A's sign bit (byte63&0x80).
     * Exercises the sign-bit restore path in verify. */
    uint8_t priv[32], pub[32], sig[64];
    static const char *msg = "signbit-test";
    unhex("1f3e5d7c9bbad9f81736557493b2d1f00f2e4d6c8baac9e80726456483a2c1e0",
          priv, 32);
    assert(wa_x25519_pub(pub, priv) == 0);
    expect_hex("xeddsa-sb-pub", pub, 32,
               "db72743e3e40db70d486a90352562cffdb5f83ef8ddd6b059f864fbbbe548147");
    assert(wa_xeddsa_sign(priv, (const uint8_t *)msg, strlen(msg), sig) == 0);
    expect_hex("xeddsa-sb-sign", sig, 64,
               "ec63253b9c89c0e435af7cb4a960681bcfa0e97ed5def0eb6eb0564451526"
               "d9ab70c8d2b39192ebdfa157991376a730bd229444de918160f90421e195ec"
               "bfb82");
    assert(sig[63] & 0x80);
    assert(wa_xeddsa_verify(pub, (const uint8_t *)msg, strlen(msg), sig) == 0);
    printf("ok: xeddsa-signbit\n");
}

/* Pairing-code primitives vs node:crypto + Baileys bytesToCrockford. */
static void t_pairing_crypto(void) {
    uint8_t salt[32], dk[32], key[32], iv[16], pt[32], ct[32];
    char code[9];
    int i;
    for (i = 0; i < 32; i++) {
        salt[i] = (uint8_t)i;
        key[i] = (uint8_t)(32 - i);
        pt[i] = (uint8_t)i;
    }
    for (i = 0; i < 16; i++)
        iv[i] = (uint8_t)i;
    assert(wa_pbkdf2_sha256("TESTCODE", salt, 32, 2u << 16, dk, 32) == 0);
    expect_hex("pbkdf2-pairing", dk, 32,
               "d67bd3d554b7912dcf7307d86c8f965119000e599815698ef28f88c68ca7c0ad");
    assert(wa_aes_ctr_encrypt(pt, 32, key, iv, ct, 32) == 32);
    expect_hex("aes-ctr-pairing", ct, 32,
               "ff1570044d426b6bc6a75cfabd65402808a34fa28068a955d9f43d529a095efa");
    {
        uint8_t b5[5] = { 1, 2, 3, 4, 5 };
        wa_crockford5(b5, code);
        assert(!strcmp(code, "15217216"));
        uint8_t c5[5] = { 0xff, 0, 0xab, 0xcd, 0xef };
        wa_crockford5(c5, code);
        assert(!strcmp(code, "ZW1BQLGG"));
    }
    printf("ok: crockford5\n");
}

/* Baileys-sequence vectors (node:crypto replica of noise-handler.ts). */
static void t_noise_vectors(void) {
    uint8_t epriv[32], seph[32], ct[64];
    wa_noise_t n;
    unhex("090e13181d22272c31363b40454a4f54595e63686d72777c81868b90959a9fa4",
          epriv, 32);
    unhex("030e19242f3a45505b66717c87929da8b3bec9d4dfeaf5000b16212c37424d58",
          seph, 32);
    wa_noise_init(&n, epriv, WA_NOISE_WA_HEADER);
    expect_hex("noise-epub", n.e_pub, 32,
               "6b30d44eb54fdfea64880ad60e0f56f400b322a7de43b8d007ff118032c99312");
    expect_hex("noise-h2", n.hash, 32,
               "6fc502f94bb8c6f766797e2350bc61d227b5a7cd9829e5a1f8aa95914163d1c5");
    assert(wa_noise_mix_server_ephemeral(&n, seph) == 0);
    expect_hex("noise-salt1", n.salt, 32,
               "8049a8609c10a8df1f5849196b12c2864e8b1ee10eada41bb2bccc3dfe1bbd8d");
    expect_hex("noise-key1", n.enc_key, 32,
               "29b465ca5f1f6c6f32f935ceb241e40a9b1d598444bbb391f14dff8002ecf977");
    int cl = wa_noise_encrypt(&n, (const uint8_t *)"test-payload", 12, ct,
                              sizeof(ct));
    assert(cl == 28);
    expect_hex("noise-ct0", ct, (size_t)cl,
               "08d0d0d0dee1bdcfc4b12251eaff389ddb7129ad168656b9d19adb8d");
    assert(wa_noise_finish_init(&n) == 0);
    expect_hex("noise-tenc", n.t_enc, 32,
               "d301c43b086ba19158142ca0b66ea2d577bfb1f667b3920b9e6229f5f33376b8");
    expect_hex("noise-tdec", n.t_dec, 32,
               "ecbfd94ef0845ae4233015f25e05b70eebbd733b48a4a0fb1cea106a4a9f8c25");
    wa_noise_free(&n);
}

/* Twin contexts with identical transcripts stay in sync (shared counter). */
static void t_noise_twins(void) {
    uint8_t epriv[32], ct[64], pt[64];
    wa_noise_t a, b;
    memset(epriv, 0x42, 32);
    wa_noise_init(&a, epriv, NULL);
    wa_noise_init(&b, epriv, NULL);
    assert(wa_noise_encrypt(&a, (const uint8_t *)"ping", 4, ct, sizeof(ct)) == 20);
    assert(wa_noise_decrypt(&b, ct, 20, pt, sizeof(pt)) == 4 &&
           memcmp(pt, "ping", 4) == 0);
    assert(wa_noise_encrypt(&b, (const uint8_t *)"pong", 4, ct, sizeof(ct)) == 20);
    assert(wa_noise_decrypt(&a, ct, 20, pt, sizeof(pt)) == 4 &&
           memcmp(pt, "pong", 4) == 0);
    assert(wa_noise_finish_init(&a) == 0 && wa_noise_finish_init(&b) == 0);
    /* Noise XX role split: initiator sends with k1/recvs with k2, responder
     * mirrors. Baileys derives [write,read]=HKDF(empty) once; the server
     * uses them swapped. Mirror b into the "server" role here. */
    for (int i = 0; i < 32; i++) {
        uint8_t tmp = b.t_enc[i];
        b.t_enc[i] = b.t_dec[i];
        b.t_dec[i] = tmp;
    }
    assert(wa_noise_transport_encrypt(&a, (const uint8_t *)"secret", 6, ct,
                                      sizeof(ct)) == 22);
    assert(wa_noise_transport_decrypt(&b, ct, 22, pt, sizeof(pt)) == 6 &&
           memcmp(pt, "secret", 6) == 0);
    wa_noise_free(&a);
    wa_noise_free(&b);
    printf("ok: noise-twin-sync+transport\n");
}

typedef struct {
    uint8_t data[16][64];
    size_t lens[16];
    int n;
} frames_t;

static int collect(const uint8_t *f, size_t len, void *user) {
    frames_t *fr = user;
    assert(fr->n < 16 && len < 64);
    memcpy(fr->data[fr->n], f, len);
    fr->lens[fr->n] = len;
    fr->n++;
    return 0;
}

static void t_frames(void) {
    wa_noise_t n, t;
    uint8_t epriv[32], out[128];
    size_t w = 0;
    frames_t fr;
    memset(epriv, 0x11, 32);

    /* pre-transport: intro header once, then bare length prefixes. */
    wa_noise_init(&n, epriv, NULL);
    assert(wa_noise_encode_frame(&n, (const uint8_t *)"AB", 2, out, sizeof(out), &w) == 0);
    assert(w == 4 + 3 + 2 && out[0] == 'W' && out[1] == 'A' &&
           out[2] == 6 && out[3] == 3);
    assert(out[4] == 0 && out[5] == 0 && out[6] == 2 && out[7] == 'A' &&
           out[8] == 'B');
    memset(&fr, 0, sizeof(fr));
    /* feed byte-at-a-time: reassembly must hold until complete.
     * (The 4-byte intro is send-side only; the peer never sees it.) */
    for (size_t i = 4; i < w; i++)
        assert(wa_noise_feed(&n, out + i, 1, collect, &fr) >= 0);
    assert(fr.n == 1 && fr.lens[0] == 2 && memcmp(fr.data[0], "AB", 2) == 0);
    /* second frame has no intro. */
    assert(wa_noise_encode_frame(&n, (const uint8_t *)"C", 1, out, sizeof(out), &w) == 0);
    assert(w == 4 && out[0] == 0 && out[1] == 0 && out[2] == 1 && out[3] == 'C');
    assert(wa_noise_feed(&n, out, w, collect, &fr) == 1);
    assert(fr.n == 2 && fr.lens[1] == 1 && fr.data[1][0] == 'C');
    wa_noise_free(&n);
    printf("ok: frames-intro+reassembly\n");

    /* transport pair with routing info in intro. */
    wa_noise_t a, b2;
    wa_noise_init(&a, epriv, NULL);
    wa_noise_init(&b2, epriv, NULL);
    memcpy(a.routing_info, "route", 5);
    a.routing_info_len = 5;
    assert(wa_noise_finish_init(&a) == 0 && wa_noise_finish_init(&b2) == 0);
    assert(wa_noise_encode_frame(&a, (const uint8_t *)"hi", 2, out, sizeof(out), &w) == 0);
    assert(w == (7 + 5 + 4) + 3 + 2 + 16);
    assert(out[0] == 'E' && out[1] == 'D');
    /* receiver skips the one-time intro, feeds the rest in two chunks. */
    memset(&fr, 0, sizeof(fr));
    wa_noise_init(&t, epriv, NULL);
    assert(wa_noise_finish_init(&t) == 0);
    for (int i = 0; i < 32; i++) { /* receiver = responder role: mirror keys */
        uint8_t tmp = t.t_enc[i];
        t.t_enc[i] = t.t_dec[i];
        t.t_dec[i] = tmp;
    }
    assert(wa_noise_feed(&t, NULL, 0, collect, &fr) == 0 && fr.n == 0);
    size_t intro = 7 + 5 + 4;
    assert(wa_noise_feed(&t, out + intro, 4, collect, &fr) == 0 && fr.n == 0);
    assert(wa_noise_feed(&t, out + intro + 4, w - intro - 4, collect, &fr) == 1);
    assert(fr.n == 1 && fr.lens[0] == 2 && memcmp(fr.data[0], "hi", 2) == 0);
    wa_noise_free(&a);
    wa_noise_free(&b2);
    wa_noise_free(&t);
    printf("ok: frames-transport+routing-intro\n");
}

static void t_zlib(void) {
    /* Server-style compressed frame: 0x02 flag + deflate(node bytes WITHOUT
     * the 0x00 envelope flag). Generated with Baileys encode + deflateSync. */
    uint8_t raw[64];
    size_t n = unhex("02789cfbc12e29c8cca2c9f187b94acf1200173b0342", raw,
                     sizeof(raw));
    wa_node_t *node = NULL;
    size_t consumed = 0;
    assert(wa_decode_node(raw, n, &node, &consumed) == 0);
    assert(consumed == n);
    assert(strcmp(node->tag, "iq") == 0);
    assert(strcmp(wa_node_get_attr(node, "to"), "s.whatsapp.net") == 0);
    assert(strcmp(wa_node_get_attr(node, "type"), "get") == 0);
    assert(strcmp(wa_node_get_attr(node, "id"), "z.9") == 0);
    wa_node_free(node);
    printf("ok: zlib-compressed-node\n");
}

int main(void) {
    t_sha256();
    t_hkdf();
    t_gcm();
    t_x25519();
    t_ed25519();
    t_xeddsa();
    t_xeddsa_sign();
    t_xeddsa_signbit();
    t_pairing_crypto();
    t_noise_vectors();
    t_noise_twins();
    t_frames();
    t_zlib();
    printf("all noise tests passed\n");
    return 0;
}

/* wa_auth.c — file-backed credential store (see wa_auth.h). */
#include "wa_auth.h"
#include "wa_crypto.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

void wa_creds_init(wa_creds_t *c) {
    if (c)
        memset(c, 0, sizeof(*c));
}

static int random_fill(uint8_t *out, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t r = fread(out, 1, n, f);
        fclose(f);
        if (r == n)
            return 0;
        return -1;
    }
    /* Fallback (not CSPRNG-strong, better than failing). */
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)(rand() & 0xff);
    return 0;
}

int wa_creds_generate(wa_creds_t *c) {
    if (!c)
        return -1;
    /* Private halves are random; public halves are X25519-derived, exactly
     * like Baileys Curve.generateKeyPair (pub stored without version byte).
     * The signed-prekey signature is real XEdDSA over 0x05||pre_pub. */
    if (random_fill(c->noise_priv, WA_KEY_LEN) ||
        random_fill(c->ident_priv, WA_KEY_LEN) ||
        random_fill(c->pre_priv, WA_KEY_LEN) ||
        random_fill(c->adv_secret, WA_ADV_LEN))
        return -1;
    if (wa_x25519_pub(c->noise_pub, c->noise_priv) ||
        wa_x25519_pub(c->ident_pub, c->ident_priv) ||
        wa_x25519_pub(c->pre_pub, c->pre_priv))
        return -1;
    {
        /* signedKeyPair(identity, keyId): sign(ident_priv, 0x05||pre_pub) */
        uint8_t msg[33];
        msg[0] = 5;
        memcpy(msg + 1, c->pre_pub, WA_KEY_LEN);
        if (wa_xeddsa_sign(c->ident_priv, msg, sizeof(msg), c->pre_sig))
            return -1;
    }
    uint8_t tmp[8];
    if (random_fill(tmp, sizeof(tmp)))
        return -1;
    c->pre_id = 1;
    c->registration_id =
        (uint32_t)((tmp[0] << 24) | (tmp[1] << 16) | (tmp[2] << 8) | tmp[3]) &
        0x3fff;
    if (c->registration_id == 0)
        c->registration_id = 1;
    c->routing_info_len = 0;
    c->next_prekey_id = 1;
    c->first_unuploaded_prekey_id = 1;
    c->registered = 0;
    return 0;
}

int wa_creds_gen_pairing(wa_creds_t *c) {
    uint8_t raw[5];
    if (!c)
        return -1;
    if (random_fill(c->pairing_eph_priv, WA_KEY_LEN) ||
        random_fill(raw, sizeof(raw)))
        return -1;
    if (wa_x25519_pub(c->pairing_eph_pub, c->pairing_eph_priv))
        return -1;
    wa_crockford5(raw, c->pairing_code);
    return 0;
}

/* ---------------- base64 ---------------- */

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int wa_b64_encode(const uint8_t *in, size_t ilen, char *out, size_t olen) {
    size_t need = ((ilen + 2) / 3) * 4 + 1;
    if (!in || !out || olen < need)
        return -1;
    size_t o = 0;
    for (size_t i = 0; i < ilen; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        int rem = (int)(ilen - i);
        if (rem > 1)
            v |= (uint32_t)in[i + 1] << 8;
        if (rem > 2)
            v |= in[i + 2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = rem > 1 ? B64[(v >> 6) & 63] : '=';
        out[o++] = rem > 2 ? B64[v & 63] : '=';
    }
    out[o] = '\0';
    return 0;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

int wa_b64_decode(const char *in, uint8_t *out, size_t olen, size_t *written) {
    if (!in || !out)
        return -1;
    size_t ilen = strlen(in);
    if (ilen % 4 != 0)
        return -1;
    size_t w = 0;
    for (size_t i = 0; i < ilen; i += 4) {
        int a = b64_val(in[i]);
        int b = b64_val(in[i + 1]);
        int c = in[i + 2] == '=' ? 0 : b64_val(in[i + 2]);
        int d = in[i + 3] == '=' ? 0 : b64_val(in[i + 3]);
        if (a < 0 || b < 0 || (in[i + 2] != '=' && c < 0) ||
            (in[i + 3] != '=' && d < 0))
            return -1;
        uint32_t v = (uint32_t)((a << 18) | (b << 12) | (c << 6) | d);
        if (w < olen)
            out[w++] = (v >> 16) & 0xff;
        if (in[i + 2] != '=') {
            if (w < olen)
                out[w++] = (v >> 8) & 0xff;
            else
                return -1;
        }
        if (in[i + 3] != '=') {
            if (w < olen)
                out[w++] = v & 0xff;
            else
                return -1;
        }
    }
    if (written)
        *written = w;
    return 0;
}

/* ---------------- JSON store ---------------- */

static int ensure_dir(const char *dir) {
    struct stat st;
    if (stat(dir, &st) == 0)
        return S_ISDIR(st.st_mode) ? 0 : -1;
    /* mkdir -p equivalent for one level (auth dir is flat). */
    if (mkdir(dir, 0700) == 0)
        return 0;
    return errno == EEXIST ? 0 : -1;
}

/* Minimal JSON string escaper for JIDs/names (no control chars expected). */
static void json_str(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        if (*s == '"' || *s == '\\')
            fputc('\\', f);
        fputc(*s, f);
    }
    fputc('"', f);
}

int wa_auth_save(const wa_creds_t *c, const char *dir) {
    char path[512];
    char b64[128];
    if (!c || !dir)
        return -1;
    if (ensure_dir(dir))
        return -1;
    snprintf(path, sizeof(path), "%s/creds.json", dir);
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;

    char k_noise_priv[64], k_noise_pub[64], k_ident_priv[64], k_ident_pub[64];
    char k_pre_priv[64], k_pre_pub[64], k_pre_sig[128], k_adv[64], k_route[128];
    wa_b64_encode(c->noise_priv, WA_KEY_LEN, k_noise_priv, sizeof(k_noise_priv));
    wa_b64_encode(c->noise_pub, WA_KEY_LEN, k_noise_pub, sizeof(k_noise_pub));
    wa_b64_encode(c->ident_priv, WA_KEY_LEN, k_ident_priv, sizeof(k_ident_priv));
    wa_b64_encode(c->ident_pub, WA_KEY_LEN, k_ident_pub, sizeof(k_ident_pub));
    wa_b64_encode(c->pre_priv, WA_KEY_LEN, k_pre_priv, sizeof(k_pre_priv));
    wa_b64_encode(c->pre_pub, WA_KEY_LEN, k_pre_pub, sizeof(k_pre_pub));
    wa_b64_encode(c->pre_sig, WA_SIG_LEN, k_pre_sig, sizeof(k_pre_sig));
    wa_b64_encode(c->adv_secret, WA_ADV_LEN, k_adv, sizeof(k_adv));
    k_route[0] = '\0';
    if (c->routing_info_len)
        wa_b64_encode(c->routing_info, c->routing_info_len, k_route,
                      sizeof(k_route));

    fprintf(f, "{\n");
    fprintf(f, "  \"noise_priv\": \"%s\",\n", k_noise_priv);
    fprintf(f, "  \"noise_pub\": \"%s\",\n", k_noise_pub);
    fprintf(f, "  \"ident_priv\": \"%s\",\n", k_ident_priv);
    fprintf(f, "  \"ident_pub\": \"%s\",\n", k_ident_pub);
    fprintf(f, "  \"pre_priv\": \"%s\",\n", k_pre_priv);
    fprintf(f, "  \"pre_pub\": \"%s\",\n", k_pre_pub);
    fprintf(f, "  \"pre_sig\": \"%s\",\n", k_pre_sig);
    fprintf(f, "  \"pre_id\": %u,\n", c->pre_id);
    fprintf(f, "  \"registration_id\": %u,\n", c->registration_id);
    fprintf(f, "  \"adv_secret\": \"%s\",\n", k_adv);
    fprintf(f, "  \"routing_info\": \"%s\",\n", k_route);
    fprintf(f, "  \"registered\": %s,\n", c->registered ? "true" : "false");
    fprintf(f, "  \"next_prekey_id\": %u,\n", c->next_prekey_id);
    fprintf(f, "  \"first_unuploaded_prekey_id\": %u,\n",
            c->first_unuploaded_prekey_id);
    fprintf(f, "  \"platform\": ");
    json_str(f, c->platform);
    {
        char pep_priv[64], pep_pub[64];
        wa_b64_encode(c->pairing_eph_priv, WA_KEY_LEN, pep_priv, sizeof(pep_priv));
        wa_b64_encode(c->pairing_eph_pub, WA_KEY_LEN, pep_pub, sizeof(pep_pub));
        fprintf(f, ",\n  \"pairing_eph_priv\": \"%s\",", pep_priv);
        fprintf(f, "\n  \"pairing_eph_pub\": \"%s\",", pep_pub);
        fprintf(f, "\n  \"pairing_code\": ");
        json_str(f, c->pairing_code);
    }
    if (c->account.present) {
        char ad[512], ak[64], as[128], ds[128];
        wa_b64_encode(c->account.details, c->account.details_len, ad, sizeof(ad));
        wa_b64_encode(c->account.account_sig_key, WA_KEY_LEN, ak, sizeof(ak));
        wa_b64_encode(c->account.account_sig, WA_SIG_LEN, as, sizeof(as));
        wa_b64_encode(c->account.device_sig, WA_SIG_LEN, ds, sizeof(ds));
        fprintf(f, ",\n  \"account_details\": \"%s\",", ad);
        fprintf(f, "\n  \"account_sig_key\": \"%s\",", ak);
        fprintf(f, "\n  \"account_sig\": \"%s\",", as);
        fprintf(f, "\n  \"account_device_sig\": \"%s\",", ds);
        fprintf(f, "\n  \"account_key_index\": %u", c->account.key_index);
    }
    fprintf(f, ",\n  \"me_id\": ");
    json_str(f, c->me_id);
    fprintf(f, ",\n  \"me_lid\": ");
    json_str(f, c->me_lid);
    fprintf(f, ",\n  \"me_name\": ");
    json_str(f, c->me_name);
    /* keep in sync with wa_b64 helpers */
    (void)b64;
    fprintf(f, "\n}\n");
    int rc = ferror(f) ? -1 : 0;
    fclose(f);
    return rc;
}

/* Tiny JSON extractor: finds "key": value (string/uint/bool). */
static int find_key(const char *json, const char *key, const char **val,
                    int *is_str) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p)
        return -1;
    p = strchr(p + strlen(pat), ':');
    if (!p)
        return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    *val = p;
    *is_str = (*p == '"');
    return 0;
}

static int get_str(const char *json, const char *key, char *out, size_t olen) {
    const char *v;
    int is_str;
    if (find_key(json, key, &v, &is_str) || !is_str)
        return -1;
    v++;
    size_t o = 0;
    while (*v && *v != '"') {
        char c = *v++;
        if (c == '\\' && *v)
            c = *v++;
        if (o + 1 < olen)
            out[o++] = c;
        else
            return -1;
    }
    out[o] = '\0';
    return *v == '"' ? 0 : -1;
}

static int get_u32(const char *json, const char *key, uint32_t *out) {
    const char *v;
    int is_str;
    if (find_key(json, key, &v, &is_str) || is_str)
        return -1;
    *out = (uint32_t)strtoul(v, NULL, 10);
    return 0;
}

static int get_b64(const char *json, const char *key, uint8_t *out,
                   size_t expect) {
    char tmp[256];
    if (get_str(json, key, tmp, sizeof(tmp)))
        return -1;
    if (tmp[0] == '\0') {
        if (expect == 0)
            return 0;
        memset(out, 0, expect);
        return 0;
    }
    size_t w = 0;
    if (wa_b64_decode(tmp, out, expect, &w) || w != expect)
        return -1;
    return 0;
}

/* Optional base64 blob (missing key -> len 0, still success). */
static int opt_b64(const char *json, const char *key, uint8_t *out,
                   size_t cap, size_t *len_out) {
    char tmp[512];
    const char *v;
    int is_str;
    *len_out = 0;
    if (find_key(json, key, &v, &is_str) || !is_str)
        return 0;
    if (get_str(json, key, tmp, sizeof(tmp)))
        return -1;
    if (!tmp[0])
        return 0;
    if (wa_b64_decode(tmp, out, cap, len_out))
        return -1;
    return 0;
}

static int opt_u32(const char *json, const char *key, uint32_t *out,
                   uint32_t dflt) {
    const char *v;
    int is_str;
    *out = dflt;
    if (find_key(json, key, &v, &is_str) || is_str)
        return 0;
    return get_u32(json, key, out);
}

int wa_auth_load(wa_creds_t *c, const char *dir) {
    char path[512];
    if (!c || !dir)
        return -1;
    wa_creds_init(c);
    snprintf(path, sizeof(path), "%s/creds.json", dir);
    FILE *f = fopen(path, "r");
    if (!f)
        return (errno == ENOENT) ? 1 : -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > 65536) {
        fclose(f);
        return -1;
    }
    char *json = malloc((size_t)sz + 1);
    if (!json) {
        fclose(f);
        return -1;
    }
    size_t r = fread(json, 1, (size_t)sz, f);
    fclose(f);
    json[r] = '\0';

    int rc = -1;
    char route[128] = "";
    uint32_t pre_id = 1, reg = 0;
    const char *v;
    int is_str;
    if (get_b64(json, "noise_priv", c->noise_priv, WA_KEY_LEN) ||
        get_b64(json, "noise_pub", c->noise_pub, WA_KEY_LEN) ||
        get_b64(json, "ident_priv", c->ident_priv, WA_KEY_LEN) ||
        get_b64(json, "ident_pub", c->ident_pub, WA_KEY_LEN) ||
        get_b64(json, "pre_priv", c->pre_priv, WA_KEY_LEN) ||
        get_b64(json, "pre_pub", c->pre_pub, WA_KEY_LEN) ||
        get_b64(json, "pre_sig", c->pre_sig, WA_SIG_LEN) ||
        get_u32(json, "pre_id", &pre_id) ||
        get_u32(json, "registration_id", &reg) ||
        get_b64(json, "adv_secret", c->adv_secret, WA_ADV_LEN) ||
        get_str(json, "routing_info", route, sizeof(route)) ||
        get_str(json, "me_id", c->me_id, sizeof(c->me_id)) ||
        get_str(json, "me_lid", c->me_lid, sizeof(c->me_lid)) ||
        get_str(json, "me_name", c->me_name, sizeof(c->me_name)))
        goto out;
    c->pre_id = pre_id;
    c->registration_id = reg;
    if (route[0]) {
        size_t w = 0;
        if (wa_b64_decode(route, c->routing_info, sizeof(c->routing_info),
                          &w))
            goto out;
        c->routing_info_len = w;
    }
    if (find_key(json, "registered", &v, &is_str) == 0 && !is_str)
        c->registered = (strncmp(v, "true", 4) == 0);
    /* new in Phase 5; absent in older sessions -> defaults */
    if (opt_u32(json, "next_prekey_id", &c->next_prekey_id, 1) ||
        opt_u32(json, "first_unuploaded_prekey_id",
                &c->first_unuploaded_prekey_id, 1))
        goto out;
    if (find_key(json, "platform", &v, &is_str) == 0 && !is_str) {
        if (get_str(json, "platform", c->platform, sizeof(c->platform)))
            goto out;
    }
    {
        size_t pl = 0, pp = 0;
        uint8_t pep[WA_KEY_LEN], qep[WA_KEY_LEN];
        if (opt_b64(json, "pairing_eph_priv", pep, sizeof(pep), &pl) == 0 &&
            pl == WA_KEY_LEN && opt_b64(json, "pairing_eph_pub", qep, sizeof(qep), &pp) == 0 &&
            pp == WA_KEY_LEN) {
            memcpy(c->pairing_eph_priv, pep, WA_KEY_LEN);
            memcpy(c->pairing_eph_pub, qep, WA_KEY_LEN);
        }
        if (find_key(json, "pairing_code", &v, &is_str) == 0 && !is_str) {
            if (get_str(json, "pairing_code", c->pairing_code,
                        sizeof(c->pairing_code)))
                goto out;
        }
    }
    {
        size_t dl = 0, kl = 0, sl = 0, dsl = 0;
        uint8_t dt[WA_ACCOUNT_DETAILS_MAX], sk[WA_KEY_LEN], sg[WA_SIG_LEN],
            dg[WA_SIG_LEN];
        uint32_t ki = 0;
        if (opt_b64(json, "account_details", dt, sizeof(dt), &dl) == 0 &&
            dl > 0 && opt_b64(json, "account_sig_key", sk, sizeof(sk), &kl) == 0 &&
            kl == WA_KEY_LEN && opt_b64(json, "account_sig", sg, sizeof(sg), &sl) == 0 &&
            sl == WA_SIG_LEN && opt_b64(json, "account_device_sig", dg, sizeof(dg), &dsl) == 0 &&
            dsl == WA_SIG_LEN && opt_u32(json, "account_key_index", &ki, 0) == 0) {
            memcpy(c->account.details, dt, dl);
            c->account.details_len = dl;
            memcpy(c->account.account_sig_key, sk, WA_KEY_LEN);
            memcpy(c->account.account_sig, sg, WA_SIG_LEN);
            memcpy(c->account.device_sig, dg, WA_SIG_LEN);
            c->account.key_index = ki;
            c->account.present = 1;
        }
    }
    rc = 0;
out:
    free(json);
    if (rc)
        wa_creds_init(c);
    return rc;
}

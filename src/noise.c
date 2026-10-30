/* wa_noise.c — Noise XX handler (see wa_noise.h). */
#include "wa_noise.h"
#include "wa_crypto.h"

#include <stdlib.h>
#include <string.h>

const char WA_NOISE_MODE[32] = "Noise_XX_25519_AESGCM_SHA256";
const uint8_t WA_NOISE_WA_HEADER[4] = { 87, 65, 6, 3 };
const uint8_t WA_CERT_PUBKEY[32] = {
    0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71, 0x66, 0xaa, 0xe7,
    0x1e, 0xbe, 0x51, 0x64, 0x37, 0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69,
    0x5c, 0x6c, 0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b
};

static void iv_for(uint32_t counter, uint8_t iv[12]) {
    memset(iv, 0, 12);
    iv[8] = (uint8_t)((counter >> 24) & 0xff);
    iv[9] = (uint8_t)((counter >> 16) & 0xff);
    iv[10] = (uint8_t)((counter >> 8) & 0xff);
    iv[11] = (uint8_t)(counter & 0xff);
}

void wa_noise_init(wa_noise_t *n, const uint8_t ephemeral_priv[32],
                   const uint8_t header[4]) {
    if (!n)
        return;
    memset(n, 0, sizeof(*n));
    if (ephemeral_priv) {
        memcpy(n->e_priv, ephemeral_priv, WA_NOISE_KEY_LEN);
        /* Derive public half (Baileys: Curve.generateKeyPair). */
        wa_x25519_pub(n->e_pub, n->e_priv);
    }
    if (header)
        memcpy(n->header, header, WA_NOISE_HEADER_LEN);
    else
        memcpy(n->header, WA_NOISE_WA_HEADER, WA_NOISE_HEADER_LEN);
    /* hash = salt = enc = dec = NOISE_MODE (already 32 bytes). */
    memcpy(n->hash, WA_NOISE_MODE, 32);
    memcpy(n->salt, WA_NOISE_MODE, 32);
    memcpy(n->enc_key, WA_NOISE_MODE, 32);
    memcpy(n->dec_key, WA_NOISE_MODE, 32);
    wa_noise_authenticate(n, n->header, WA_NOISE_HEADER_LEN);
    wa_noise_authenticate(n, n->e_pub, WA_NOISE_KEY_LEN);
}

void wa_noise_free(wa_noise_t *n) {
    if (!n)
        return;
    free(n->inbuf);
    n->inbuf = NULL;
    n->inlen = n->incap = 0;
}

int wa_noise_authenticate(wa_noise_t *n, const uint8_t *data, size_t len) {
    uint8_t *tmp;
    if (!n || (!data && len))
        return -1;
    if (n->transport)
        return 0; /* Baileys: no-op once transport is up */
    tmp = malloc(32 + len);
    if (!tmp)
        return -1;
    memcpy(tmp, n->hash, 32);
    memcpy(tmp + 32, data, len);
    wa_sha256(tmp, 32 + len, n->hash);
    free(tmp);
    return 0;
}

int wa_noise_encrypt(wa_noise_t *n, const uint8_t *in, size_t ilen,
                     uint8_t *out, size_t olen) {
    uint8_t iv[12];
    int rc;
    if (!n || n->transport)
        return -1;
    iv_for(n->counter++, iv);
    rc = wa_aes_gcm_encrypt(in, ilen, n->enc_key, iv, n->hash, 32, out, olen);
    if (rc < 0)
        return -1;
    if (wa_noise_authenticate(n, out, (size_t)rc))
        return -1;
    return rc;
}

int wa_noise_decrypt(wa_noise_t *n, const uint8_t *in, size_t ilen,
                     uint8_t *out, size_t olen) {
    uint8_t iv[12];
    int rc;
    if (!n || n->transport)
        return -1;
    iv_for(n->counter++, iv);
    rc = wa_aes_gcm_decrypt(in, ilen, n->dec_key, iv, n->hash, 32, out, olen);
    if (rc < 0)
        return -1;
    if (wa_noise_authenticate(n, in, ilen))
        return -1;
    return rc;
}

int wa_noise_mix_key(wa_noise_t *n, const uint8_t *secret, size_t slen) {
    uint8_t okm[64];
    if (!n || !secret)
        return -1;
    if (wa_hkdf_sha256(okm, sizeof(okm), secret, slen, n->salt, 32, NULL, 0))
        return -1;
    memcpy(n->salt, okm, 32);
    memcpy(n->enc_key, okm + 32, 32);
    memcpy(n->dec_key, okm + 32, 32);
    n->counter = 0;
    return 0;
}

int wa_noise_finish_init(wa_noise_t *n) {
    static const uint8_t empty = 0;
    uint8_t okm[64];
    if (!n || n->transport)
        return -1;
    if (wa_hkdf_sha256(okm, sizeof(okm), &empty, 0, n->salt, 32, NULL, 0))
        return -1;
    memcpy(n->t_enc, okm, 32);
    memcpy(n->t_dec, okm + 32, 32);
    n->read_counter = n->write_counter = 0;
    n->transport = 1;
    return 0;
}

int wa_noise_mix_server_ephemeral(wa_noise_t *n,
                                  const uint8_t server_eph[32]) {
    uint8_t shared[32];
    if (!n || !server_eph)
        return -1;
    memcpy(n->server_eph, server_eph, 32);
    n->have_server_eph = 1;
    if (wa_noise_authenticate(n, server_eph, 32))
        return -1;
    if (wa_x25519_shared(shared, n->e_priv, server_eph))
        return -1;
    return wa_noise_mix_key(n, shared, 32);
}

int wa_noise_mix_static(wa_noise_t *n, const uint8_t static_pub[32]) {
    uint8_t shared[32];
    if (!n || !static_pub)
        return -1;
    if (wa_x25519_shared(shared, n->e_priv, static_pub))
        return -1;
    return wa_noise_mix_key(n, shared, 32);
}

int wa_noise_encrypt_static(wa_noise_t *n, const uint8_t noise_pub[32],
                            const uint8_t noise_priv[32], uint8_t out[48]) {
    uint8_t shared[32];
    int rc;
    if (!n || !noise_pub || !noise_priv || !n->have_server_eph)
        return -1;
    rc = wa_noise_encrypt(n, noise_pub, 32, out, 48);
    if (rc != 48)
        return -1;
    if (wa_x25519_shared(shared, noise_priv, n->server_eph))
        return -1;
    if (wa_noise_mix_key(n, shared, 32))
        return -1;
    return 48;
}

int wa_noise_transport_encrypt(wa_noise_t *n, const uint8_t *in, size_t ilen,
                               uint8_t *out, size_t olen) {
    static const uint8_t empty = 0;
    uint8_t iv[12];
    if (!n || !n->transport)
        return -1;
    iv_for(n->write_counter++, iv);
    return wa_aes_gcm_encrypt(in, ilen, n->t_enc, iv, &empty, 0, out, olen);
}

int wa_noise_transport_decrypt(wa_noise_t *n, const uint8_t *in, size_t ilen,
                               uint8_t *out, size_t olen) {
    static const uint8_t empty = 0;
    uint8_t iv[12];
    if (!n || !n->transport)
        return -1;
    iv_for(n->read_counter++, iv);
    return wa_aes_gcm_decrypt(in, ilen, n->t_dec, iv, &empty, 0, out, olen);
}

static int intro_len(const wa_noise_t *n) {
    if (n->routing_info_len)
        return (int)(7 + n->routing_info_len + WA_NOISE_HEADER_LEN);
    return WA_NOISE_HEADER_LEN;
}

int wa_noise_encode_frame(wa_noise_t *n, const uint8_t *payload,
                          size_t plen, uint8_t *out, size_t olen,
                          size_t *written) {
    uint8_t tmp[65536 + 16];
    const uint8_t *data = payload;
    size_t dlen = plen;
    int intro = 0;
    if (!n || (!payload && plen))
        return -1;
    if (n->transport) {
        int rc = wa_noise_transport_encrypt(n, payload, plen, tmp,
                                            sizeof(tmp));
        if (rc < 0)
            return -1;
        data = tmp;
        dlen = (size_t)rc;
    }
    if (dlen > 0xffffff)
        return -1;
    if (!n->intro_sent)
        intro = intro_len(n);
    if (olen < (size_t)intro + 3 + dlen)
        return -1;
    size_t pos = 0;
    if (!n->intro_sent) {
        if (n->routing_info_len) {
            out[0] = 'E';
            out[1] = 'D';
            out[2] = 0;
            out[3] = 1;
            out[4] = (uint8_t)(n->routing_info_len >> 16);
            out[5] = (uint8_t)((n->routing_info_len >> 8) & 0xff);
            out[6] = (uint8_t)(n->routing_info_len & 0xff);
            memcpy(out + 7, n->routing_info, n->routing_info_len);
            memcpy(out + 7 + n->routing_info_len, n->header,
                   WA_NOISE_HEADER_LEN);
        } else {
            memcpy(out, n->header, WA_NOISE_HEADER_LEN);
        }
        pos = (size_t)intro;
        n->intro_sent = 1;
    }
    out[pos] = (uint8_t)((dlen >> 16) & 0xff);
    out[pos + 1] = (uint8_t)((dlen >> 8) & 0xff);
    out[pos + 2] = (uint8_t)(dlen & 0xff);
    memcpy(out + pos + 3, data, dlen);
    if (written)
        *written = pos + 3 + dlen;
    return 0;
}

int wa_noise_pending(const wa_noise_t *n) {
    size_t size;
    if (!n || n->inlen < 3)
        return 0;
    size = ((size_t)n->inbuf[0] << 16) | ((size_t)n->inbuf[1] << 8) |
           n->inbuf[2];
    return n->inlen >= size + 3;
}

int wa_noise_feed(wa_noise_t *n, const uint8_t *data, size_t len,
                  wa_frame_cb cb, void *user) {
    int frames = 0;
    if (!n || (!data && len) || !cb)
        return -1;
    if (len) {
        if (n->inlen + len > n->incap) {
            size_t ncap = n->incap ? n->incap * 2 : 4096;
            while (ncap < n->inlen + len)
                ncap *= 2;
            if (ncap > 10 * 1024 * 1024)
                return -1; /* Baileys MAX_BUFFER_SIZE guard */
            uint8_t *nb = realloc(n->inbuf, ncap);
            if (!nb)
                return -1;
            n->inbuf = nb;
            n->incap = ncap;
        }
        memcpy(n->inbuf + n->inlen, data, len);
        n->inlen += len;
    }
    while (n->inlen >= 3) {
        size_t size = ((size_t)n->inbuf[0] << 16) |
                      ((size_t)n->inbuf[1] << 8) | n->inbuf[2];
        if (n->inlen < size + 3)
            break;
        int rc;
        if (n->transport) {
            /* Decrypt in place (plaintext is shorter than ciphertext). */
            rc = wa_noise_transport_decrypt(n, n->inbuf + 3, size, n->inbuf + 3,
                                            size);
            if (rc < 0)
                return -1;
            rc = cb(n->inbuf + 3, (size_t)rc, user);
        } else {
            rc = cb(n->inbuf + 3, size, user);
        }
        memmove(n->inbuf, n->inbuf + size + 3, n->inlen - size - 3);
        n->inlen -= size + 3;
        frames++;
        if (rc != 0)
            return rc > 0 ? frames : rc;
    }
    return frames;
}

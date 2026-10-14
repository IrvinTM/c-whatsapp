/* wa_ws.c — minimal WSS client (see wa_ws.h). */
#define _POSIX_C_SOURCE 200809L

#include "wa_ws.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#define WA_WS_OP_CONT 0x0
#define WA_WS_OP_TEXT 0x1
#define WA_WS_OP_BIN 0x2
#define WA_WS_OP_CLOSE 0x8
#define WA_WS_OP_PING 0x9
#define WA_WS_OP_PONG 0xa

static int wait_fd(int fd, int wr, int timeout_ms) {
    fd_set set;
    struct timeval tv;
    FD_ZERO(&set);
    FD_SET(fd, &set);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int rc = select(fd + 1, wr ? NULL : &set, wr ? &set : NULL, NULL,
                    timeout_ms < 0 ? NULL : &tv);
    return rc == 1 ? 0 : -1;
}

/* Full write through SSL (handles WANT_READ/WRITE). */
static int ssl_write_all(SSL *ssl, int fd, const uint8_t *p, size_t n,
                         int timeout_ms) {
    while (n) {
        int rc = SSL_write(ssl, p, (int)n);
        if (rc > 0) {
            p += rc;
            n -= (size_t)rc;
            continue;
        }
        int err = SSL_get_error(ssl, rc);
        if (err == SSL_ERROR_WANT_READ) {
            if (wait_fd(fd, 0, timeout_ms))
                return -1;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            if (wait_fd(fd, 1, timeout_ms))
                return -1;
        } else {
            return -1;
        }
    }
    return 0;
}

/* Read exactly n bytes through SSL (handles WANT_READ/WRITE). */
static int ssl_read_all(SSL *ssl, int fd, uint8_t *p, size_t n,
                        int timeout_ms) {
    while (n) {
        if (SSL_pending(ssl) <= 0 && wait_fd(fd, 0, timeout_ms))
            return -1;
        int rc = SSL_read(ssl, p, (int)n);
        if (rc > 0) {
            p += rc;
            n -= (size_t)rc;
            continue;
        }
        int err = SSL_get_error(ssl, rc);
        if (err == SSL_ERROR_WANT_READ) {
            if (wait_fd(fd, 0, timeout_ms))
                return -1;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            if (wait_fd(fd, 1, timeout_ms))
                return -1;
        } else {
            return -1;
        }
    }
    return 0;
}

/* Read HTTP response headers until \r\n\r\n (cap 16KB). */
static int read_http_response(SSL *ssl, int fd, char *out, size_t olen,
                              int timeout_ms) {
    size_t pos = 0;
    while (pos + 1 < olen) {
        if (ssl_read_all(ssl, fd, (uint8_t *)out + pos, 1, timeout_ms))
            return -1;
        pos++;
        if (pos >= 4 && !memcmp(out + pos - 4, "\r\n\r\n", 4)) {
            out[pos] = '\0';
            return 0;
        }
    }
    return -1;
}

int wa_ws_connect(wa_ws_t *ws, const char *host, const char *port,
                  const char *path_query, const char *origin, int timeout_ms) {
    struct addrinfo hints, *list = NULL, *ai;
    int fd = -1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char req[2048];
    char resp[16384];
    uint8_t key_raw[16];
    char key_b64[32];
    int rc = -1;

    if (!ws || !host || !port || !path_query)
        return -1;
    memset(ws, 0, sizeof(*ws));
    ws->fd = -1;

    /* base64(16 random bytes) for Sec-WebSocket-Key */
    {
        static const char *B64 =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        size_t o = 0;
        if (RAND_bytes(key_raw, sizeof(key_raw)) != 1)
            return -1;
        for (int i = 0; i < 16; i += 3) {
            uint32_t v = (uint32_t)key_raw[i] << 16 |
                         (uint32_t)key_raw[i + 1] << 8 | key_raw[i + 2];
            key_b64[o++] = B64[(v >> 18) & 63];
            key_b64[o++] = B64[(v >> 12) & 63];
            key_b64[o++] = B64[(v >> 6) & 63];
            key_b64[o++] = B64[v & 63];
        }
        /* 16 bytes -> 24 chars with one '=' pad */
        key_b64[22] = '=';
        key_b64[23] = '=';
        key_b64[24] = '\0';
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &list))
        return -1;
    for (ai = list; ai; ai = ai->ai_next) {
        int flags, err;
        socklen_t errlen = sizeof(err);
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        if (errno != EINPROGRESS) {
            close(fd);
            fd = -1;
            continue;
        }
        if (wait_fd(fd, 1, timeout_ms) || getsockopt(fd, SOL_SOCKET, SO_ERROR,
                                                     &err, &errlen) ||
            err) {
            close(fd);
            fd = -1;
            continue;
        }
        break;
    }
    freeaddrinfo(list);
    if (fd < 0)
        return -1;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        goto fail;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(ctx);
    ssl = SSL_new(ctx);
    if (!ssl)
        goto fail;
    SSL_set_tlsext_host_name(ssl, host);
    SSL_set1_host(ssl, host);
    SSL_set_fd(ssl, fd);
    for (;;) {
        int r = SSL_connect(ssl);
        if (r == 1)
            break;
        int err = SSL_get_error(ssl, r);
        if (err == SSL_ERROR_WANT_READ) {
            if (wait_fd(fd, 0, timeout_ms))
                goto fail;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            if (wait_fd(fd, 1, timeout_ms))
                goto fail;
        } else {
            goto fail;
        }
    }
    if (SSL_get_verify_result(ssl) != X509_V_OK)
        goto fail;

    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n"
             "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
             "Sec-WebSocket-Version: 13\r\nOrigin: %s\r\n\r\n",
             path_query, host, key_b64, origin ? origin : "");
    if (ssl_write_all(ssl, fd, (const uint8_t *)req, strlen(req), timeout_ms))
        goto fail;
    if (read_http_response(ssl, fd, resp, sizeof(resp), timeout_ms))
        goto fail;
    if (strncmp(resp, "HTTP/1.1 101", 12) && strncmp(resp, "HTTP/1.0 101", 12))
        goto fail;

    ws->fd = fd;
    ws->ssl = ssl;
    ws->ctx = ctx;
    return 0;
fail:
    rc = -1;
    if (ssl)
        SSL_free(ssl);
    if (ctx)
        SSL_CTX_free(ctx);
    if (fd >= 0)
        close(fd);
    return rc;
}

static int ws_send_frame(wa_ws_t *ws, uint8_t opcode, const uint8_t *data,
                         size_t len) {
    uint8_t hdr[14];
    size_t hlen = 0;
    uint8_t mask[4];
    SSL *ssl = ws->ssl;
    hdr[0] = 0x80 | opcode;
    if (len < 126) {
        hdr[1] = 0x80 | (uint8_t)len;
        hlen = 2;
    } else if (len < 65536) {
        hdr[1] = 0x80 | 126;
        hdr[2] = (uint8_t)(len >> 8);
        hdr[3] = (uint8_t)len;
        hlen = 4;
    } else {
        hdr[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++)
            hdr[2 + i] = (uint8_t)(len >> (56 - 8 * i));
        hlen = 10;
    }
    if (RAND_bytes(mask, 4) != 1)
        return -1;
    memcpy(hdr + hlen, mask, 4);
    hlen += 4;
    if (ssl_write_all(ssl, ws->fd, hdr, hlen, 20000))
        return -1;
    /* masked payload in chunks (avoid a second copy of huge frames). */
    {
        uint8_t chunk[8192];
        size_t off = 0;
        while (off < len) {
            size_t n = len - off > sizeof(chunk) ? sizeof(chunk) : len - off;
            for (size_t i = 0; i < n; i++)
                chunk[i] = data[off + i] ^ mask[(off + i) % 4];
            if (ssl_write_all(ssl, ws->fd, chunk, n, 20000))
                return -1;
            off += n;
        }
    }
    return 0;
}

int wa_ws_send_bin(wa_ws_t *ws, const uint8_t *data, size_t len) {
    if (!ws || !ws->ssl || (!data && len))
        return -1;
    return ws_send_frame(ws, WA_WS_OP_BIN, data, len);
}

int wa_ws_send_ping(wa_ws_t *ws) {
    if (!ws || !ws->ssl)
        return -1;
    return ws_send_frame(ws, WA_WS_OP_PING, NULL, 0);
}

/* Read one WS frame header + payload (caller frees payload). */
static int ws_read_frame(wa_ws_t *ws, uint8_t *opcode, int *fin,
                         uint8_t **payload, size_t *paylen, int timeout_ms) {
    SSL *ssl = ws->ssl;
    uint8_t hdr[2];
    uint64_t len;
    uint8_t *buf;
    int masked;
    if (ssl_read_all(ssl, ws->fd, hdr, 2, timeout_ms))
        return -1;
    *fin = (hdr[0] & 0x80) != 0;
    *opcode = hdr[0] & 0x0f;
    masked = (hdr[1] & 0x80) != 0;
    len = hdr[1] & 0x7f;
    if (len == 126) {
        uint8_t ext[2];
        if (ssl_read_all(ssl, ws->fd, ext, 2, timeout_ms))
            return -1;
        len = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (len == 127) {
        uint8_t ext[8];
        uint64_t v = 0;
        if (ssl_read_all(ssl, ws->fd, ext, 8, timeout_ms))
            return -1;
        for (int i = 0; i < 8; i++)
            v = (v << 8) | ext[i];
        if (v >> 63)
            return -1;
        len = v;
    }
    if (len > 16 * 1024 * 1024)
        return -1;
    uint8_t mask[4] = { 0, 0, 0, 0 };
    if (masked && ssl_read_all(ssl, ws->fd, mask, 4, timeout_ms))
        return -1;
    buf = malloc(len ? len : 1);
    if (!buf)
        return -1;
    if (len && ssl_read_all(ssl, ws->fd, buf, (size_t)len, timeout_ms)) {
        free(buf);
        return -1;
    }
    if (masked)
        for (uint64_t i = 0; i < len; i++)
            buf[i] ^= mask[i % 4];
    *payload = buf;
    *paylen = (size_t)len;
    return 0;
}

wa_ws_msg_t wa_ws_recv(wa_ws_t *ws, uint8_t **payload, size_t *len,
                       int timeout_ms) {
    uint8_t *msg = NULL;
    size_t msglen = 0;
    *payload = NULL;
    *len = 0;
    if (!ws || !ws->ssl)
        return WA_WS_ERR;
    for (;;) {
        uint8_t op;
        int fin;
        uint8_t *p = NULL;
        size_t n = 0;
        if (SSL_pending(ws->ssl) <= 0 && wait_fd(ws->fd, 0, timeout_ms)) {
            free(msg);
            return WA_WS_TIMEOUT;
        }
        if (ws_read_frame(ws, &op, &fin, &p, &n, timeout_ms)) {
            free(msg);
            return WA_WS_ERR;
        }
        if (op == WA_WS_OP_BIN || op == WA_WS_OP_TEXT || op == WA_WS_OP_CONT) {
            uint8_t *nm = realloc(msg, msglen + n);
            if (!nm) {
                free(msg);
                free(p);
                return WA_WS_ERR;
            }
            msg = nm;
            memcpy(msg + msglen, p, n);
            msglen += n;
            free(p);
            if (!fin)
                continue; /* more fragments coming */
            *payload = msg;
            *len = msglen;
            return WA_WS_BIN;
        }
        if (op == WA_WS_OP_PING) {
            ws_send_frame(ws, WA_WS_OP_PONG, p, n);
            free(p);
            continue;
        }
        if (op == WA_WS_OP_PONG) {
            free(p);
            continue;
        }
        if (op == WA_WS_OP_CLOSE) {
            ws_send_frame(ws, WA_WS_OP_CLOSE, NULL, 0);
            free(p);
            free(msg);
            return WA_WS_CLOSE;
        }
        free(p);
        free(msg);
        return WA_WS_ERR;
    }
}

void wa_ws_close(wa_ws_t *ws) {
    if (!ws)
        return;
    if (ws->ssl) {
        SSL_shutdown(ws->ssl);
        SSL_free(ws->ssl);
        ws->ssl = NULL;
    }
    if (ws->ctx) {
        SSL_CTX_free(ws->ctx);
        ws->ctx = NULL;
    }
    if (ws->fd >= 0) {
        close(ws->fd);
        ws->fd = -1;
    }
}

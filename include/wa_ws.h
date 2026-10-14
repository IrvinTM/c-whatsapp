/* wa_ws.h — minimal WebSocket-over-TLS client.
 *
 * Covers exactly what the WhatsApp handshake needs: TCP connect, TLS with
 * SNI + cert verification, HTTP Upgrade, masked binary sends, fragmented
 * receives, ping/pong, close. No external deps beyond OpenSSL.
 */
#ifndef WA_WS_H
#define WA_WS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int fd;
    void *ssl; /* SSL* (opaque here to keep OpenSSL out of headers) */
    void *ctx; /* SSL_CTX* */
} wa_ws_t;

typedef enum {
    WA_WS_BIN = 0, /* binary or text frame payload */
    WA_WS_CLOSE, /* clean close from peer (or local error after) */
    WA_WS_TIMEOUT, /* nothing arrived within timeout_ms */
    WA_WS_ERR /* transport/TLS/protocol error */
} wa_ws_msg_t;

int wa_ws_connect(wa_ws_t *ws, const char *host, const char *port,
                  const char *path_query, const char *origin, int timeout_ms);
int wa_ws_send_bin(wa_ws_t *ws, const uint8_t *data, size_t len);
int wa_ws_send_ping(wa_ws_t *ws);
/* On WA_WS_BIN, *payload is malloc'd (caller frees). */
wa_ws_msg_t wa_ws_recv(wa_ws_t *ws, uint8_t **payload, size_t *len,
                       int timeout_ms);
void wa_ws_close(wa_ws_t *ws);

#ifdef __cplusplus
}
#endif

#endif /* WA_WS_H */

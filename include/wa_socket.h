/* wa_socket.h — WhatsApp connection flow (Phase 4).
 *
 * Mirrors Baileys makeSocket validateConnection + the QR pair-device flow:
 * WSS connect -> ClientHello -> ServerHello/Noise XX -> registration or
 * login ClientPayload -> ClientFinish -> dispatch loop (pair-device QR,
 * pair-success restart, success open).
 *
 * Pair-success crypto (ADV verify + XEdDSA sign) and pairing-code login
 * arrive with the Signal layer (Phase 5); the dispatcher reports them as
 * WA_RUN_RESTART so callers reconnect like Baileys does.
 */
#ifndef WA_SOCKET_H
#define WA_SOCKET_H

#include "wa_auth.h"
#include "wa_binary.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WA_WS_URL "wss://web.whatsapp.com/ws/chat"
#define WA_WS_HOST "web.whatsapp.com"
#define WA_WS_PORT "443"
#define WA_WS_PATH "/ws/chat"
#define WA_ORIGIN "https://web.whatsapp.com"
#define WA_TAG_MAX 32

typedef enum {
    WA_CONN_CLOSE = 0,
    WA_CONN_CONNECTING,
    WA_CONN_QR, /* QR string ready to render */
    WA_CONN_OPEN
} wa_conn_state_t;

typedef struct {
    wa_conn_state_t state;
    wa_creds_t *creds;
    char last_qr[1024];
    unsigned long msg_tag_counter;
} wa_conn_t;

void wa_conn_init(wa_conn_t *c, wa_creds_t *creds);
int wa_conn_close(wa_conn_t *c);
int wa_conn_send_node(wa_conn_t *c, const wa_node_t *node); /* TODO Phase 5 */
void wa_conn_next_tag(wa_conn_t *c, char out[WA_TAG_MAX]);

/* Run outcome. */
#define WA_RUN_OPEN 0 /* logged in, connection open */
#define WA_RUN_ERROR 1 /* transport/handshake failure */
#define WA_RUN_RESTART 2 /* paired (or logged out remotely): reconnect */
#define WA_RUN_TIMEOUT 3 /* overall timeout hit */

typedef struct {
    void (*on_qr)(const char *qr, void *user);
    void (*on_pair_code)(const char *code, void *user);
    void (*on_open)(void *user);
    void (*on_close)(const char *reason, void *user);
    void (*on_log)(const char *msg, void *user);
    /* Called for each successfully decrypted inbound text message. */
    void (*on_message)(const char *from, const char *text, void *user);
    void *user;
    const char *push_name; /* optional, NULL = omit */
    const char *pair_number; /* optional: digits+country code for code pairing */
    const char *auth_dir; /* saved on creds updates (like creds.update) */
    const char *to_jid; /* optional: 1:1 send destination (phone or JID) */
    const char *text; /* optional: text to send with to_jid */
    int daemon; /* keep running, poll reminders.tsv and send due */
    int listen; /* stay online and handle inbound messages (no polling) */
    int read_receipts; /* send read receipts for inbound messages */
    int receipt_wait_ms; /* post-send receipt listen (0 = 15000) */
    /* Comma-separated phone numbers allowed to manage reminders over chat
     * (CWA_ALLOW). NULL/empty disables chat commands entirely. */
    const char *allow;
    int connect_timeout_ms; /* 0 = 20000 */
    int run_timeout_ms; /* 0 = no overall timeout */
} wa_conn_opts_t;

/* Blocking: runs the full flow, invoking callbacks. Returns WA_RUN_*. */
int wa_conn_run(wa_creds_t *creds, const wa_conn_opts_t *opts);

#ifdef __cplusplus
}
#endif

#endif /* WA_SOCKET_H */

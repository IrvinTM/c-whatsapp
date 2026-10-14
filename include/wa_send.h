/* wa_send.h — message sending (Phase 5).
 *
 * Mirrors Baileys sendMessage(): Signal-encrypts a chat protobuf and
 * relays it as a binary-node stanza. Requires authenticated connection
 * + Signal session setup, hence stubbed until Phase 5.
 */
#ifndef WA_SEND_H
#define WA_SEND_H

#include "wa_socket.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Send a 1:1 text message. Returns 0 on success, -ENOSYS until Phase 5. */
int wa_send_text(wa_conn_t *c, const char *to_jid, const char *text);

#ifdef __cplusplus
}
#endif

#endif /* WA_SEND_H */

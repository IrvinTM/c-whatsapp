/* Send stubs — Signal encryption + relay land in Phase 5. */
#include "wa_send.h"

#include <errno.h>

int wa_send_text(wa_conn_t *c, const char *to_jid, const char *text) {
    (void)c;
    (void)to_jid;
    (void)text;
    return -ENOSYS;
}

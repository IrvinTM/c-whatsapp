/* wa_pairing.h — pair-success handling (configureSuccessfulPairing port).
 *
 * Verifies the account signature chain (HMAC-SHA256 with the ADV secret,
 * XEdDSA account signature), signs our device signature, and builds the
 * pair-device-sign reply. On success the caller sends the reply, saves
 * creds, and reconnects (Baileys restart flow).
 */
#ifndef WA_PAIRING_H
#define WA_PAIRING_H

#include "wa_auth.h"
#include "wa_binary.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ADV signature prefixes (Baileys Defaults). */
extern const uint8_t WA_ADV_ACCOUNT_SIG_PREFIX[2]; /* 06 00 */
extern const uint8_t WA_ADV_DEVICE_SIG_PREFIX[2]; /* 06 01 */
extern const uint8_t WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX[2]; /* 06 05 */

/* Applies pairing to creds and builds the reply iq node (caller frees).
 * Returns 0 on success, -1 on verification/format failure. */
int wa_pair_success(wa_creds_t *creds, const wa_node_t *stanza,
                    wa_node_t **reply_out);

#ifdef __cplusplus
}
#endif

#endif /* WA_PAIRING_H */

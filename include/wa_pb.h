/* wa_pb.h — minimal protobuf codec for the WhatsApp handshake.
 *
 * Field numbers mirror Baileys WAProto (WAProto/WAProto.proto @74af8eee).
 * Only the messages needed for auth are implemented:
 *   HandshakeMessage.{clientHello,serverHello,clientFinish},
 *   ClientPayload (+UserAgent/WebInfo/DevicePairingRegistrationData),
 *   DeviceProps (+AppVersion/HistorySyncConfig),
 *   CertChain.NoiseCertificate(.Details).
 *
 * Like protobufjs with `optional` fields, explicitly-set values — including
 * false/0 — are encoded; absent ones are omitted.
 */
#ifndef WA_PB_H
#define WA_PB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* wire types */
#define WA_PB_VARINT 0
#define WA_PB_64BIT 1
#define WA_PB_LEN 2
#define WA_PB_32BIT 5

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} wa_pbw_t;

void wa_pbw_init(wa_pbw_t *w);
void wa_pbw_free(wa_pbw_t *w);
int wa_pbw_reserve(wa_pbw_t *w, size_t extra);
int wa_pbw_tag(wa_pbw_t *w, uint32_t field, uint32_t wire);
int wa_pbw_varint(wa_pbw_t *w, uint64_t v);
int wa_pbw_u32(wa_pbw_t *w, uint32_t field, uint32_t v);
int wa_pbw_u64(wa_pbw_t *w, uint32_t field, uint64_t v);
int wa_pbw_bool(wa_pbw_t *w, uint32_t field, int v);
int wa_pbw_bytes(wa_pbw_t *w, uint32_t field, const uint8_t *d, size_t n);
int wa_pbw_str(wa_pbw_t *w, uint32_t field, const char *s);
int wa_pbw_msg(wa_pbw_t *w, uint32_t field, const wa_pbw_t *sub);
int wa_pbw_raw(wa_pbw_t *w, const uint8_t *d, size_t n);

/* reader */
typedef struct {
    const uint8_t *p;
    size_t len;
    size_t pos;
} wa_pbr_t;

typedef struct {
    uint32_t field;
    uint32_t wire;
    uint64_t varint; /* VARINT */
    const uint8_t *data; /* LEN */
    size_t datalen; /* LEN */
} wa_pbf_t;

/* Returns 1 = field read, 0 = end of input, -1 = malformed. */
int wa_pbr_next(wa_pbr_t *r, wa_pbf_t *f);

/* ---- typed messages ---- */

int wa_pb_encode_client_hello(const uint8_t eph[32], wa_pbw_t *out);
int wa_pb_encode_client_finish(const uint8_t *st, size_t stlen,
                               const uint8_t *pay, size_t paylen,
                               wa_pbw_t *out);

/* ServerHello fields; *stat and *pay are malloc'd (caller frees). */
int wa_pb_decode_server_hello(const uint8_t *msg, size_t len,
                              uint8_t eph[32], uint8_t **stat, size_t *statlen,
                              uint8_t **pay, size_t *paylen);

typedef struct {
    uint8_t *leaf_details;
    size_t leaf_details_len;
    uint8_t *leaf_sig;
    size_t leaf_sig_len;
    uint8_t *int_details;
    size_t int_details_len;
    uint8_t *int_sig;
    size_t int_sig_len;
} wa_certchain_t;

void wa_certchain_free(wa_certchain_t *c);
int wa_pb_decode_cert_chain(const uint8_t *msg, size_t len, wa_certchain_t *out);
int wa_pb_decode_cert_details(const uint8_t *msg, size_t len,
                              uint32_t *serial, uint32_t *issuer,
                              const uint8_t **key, size_t *keylen);

/* ClientPayload builders. push_name may be NULL (omitted). */
int wa_pb_encode_registration(const uint8_t ident_pub[32],
                              const uint8_t pre_pub[32],
                              const uint8_t pre_sig[64], uint32_t pre_id,
                              uint32_t registration_id, const char *push_name,
                              wa_pbw_t *out);
int wa_pb_encode_login(uint64_t username, int have_device, uint32_t device,
                       const char *push_name, wa_pbw_t *out);

/* ADV account encryption type. */
#define WA_ADV_E2EE 0
#define WA_ADV_HOSTED 1

/* ADVSignedDeviceIdentityHMAC decode. hmac must hold 32 bytes. */
int wa_pb_decode_adv_hmac(const uint8_t *msg, size_t len, const uint8_t **details,
                          size_t *details_len, uint8_t hmac[32],
                          int *account_type);
/* ADVSignedDeviceIdentity decode (borrowed pointers). */
int wa_pb_decode_adv_account(const uint8_t *msg, size_t len,
                             const uint8_t **details, size_t *details_len,
                             const uint8_t **sigkey, size_t *sigkey_len,
                             const uint8_t **sig, size_t *sig_len,
                             const uint8_t **devsig, size_t *devsig_len);
/* ADVDeviceIdentity decode. */
int wa_pb_decode_adv_device(const uint8_t *msg, size_t len,
                            uint32_t *key_index, int *device_type);
/* ADV encoders (deviceSignature/accountSignatureKey may be NULL). */
int wa_pb_encode_adv_device(uint32_t key_index, int device_type, wa_pbw_t *out);
int wa_pb_encode_adv_account(const uint8_t *details, size_t details_len,
                             const uint8_t *sigkey, size_t sigkey_len,
                             const uint8_t *sig, size_t sig_len,
                             const uint8_t *devsig, size_t devsig_len,
                             wa_pbw_t *out);
int wa_pb_encode_adv_hmac(const uint8_t *details, size_t details_len,
                          const uint8_t hmac[32], int have_type,
                          int account_type, wa_pbw_t *out);

/* "2.3000.1043857760" style version used for the build-hash MD5. */
#define WA_APP_VERSION_STR "2.3000.1043857760"

/* Phase 5 (send): minimal message + Signal protobuf encoders. */
int wa_pb_encode_wamessage_text(const char *text, wa_pbw_t *out);
int wa_pb_encode_whisper(const uint8_t *eph_33, uint32_t counter,
                         uint32_t prev_counter, const uint8_t *ct,
                         size_t ct_len, wa_pbw_t *out);
int wa_pb_encode_prekey_msg(const uint8_t *identity_33,
                            const uint8_t *base_33,
                            uint32_t registration_id, uint32_t signed_prekey_id,
                            int have_prekey_id, uint32_t prekey_id,
                            const uint8_t *inner, size_t inner_len,
                            wa_pbw_t *out);

/* Phase 5 (recv): Signal + WAMessage decoders (borrowed pointers). */
typedef struct {
    const uint8_t *ephemeral_key;
    size_t ephemeral_key_len;
    uint32_t counter;
    int has_counter;
    uint32_t previous_counter;
    int has_previous_counter;
    const uint8_t *ciphertext;
    size_t ciphertext_len;
} wa_pb_whisper_t;

int wa_pb_decode_whisper(const uint8_t *msg, size_t len, wa_pb_whisper_t *out);

typedef struct {
    uint32_t prekey_id;
    int has_prekey_id;
    const uint8_t *base_key;
    size_t base_key_len;
    const uint8_t *identity_key;
    size_t identity_key_len;
    const uint8_t *message;
    size_t message_len;
    uint32_t registration_id;
    int has_registration_id;
    uint32_t signed_prekey_id;
    int has_signed_prekey_id;
} wa_pb_prekey_t;

int wa_pb_decode_prekey_msg(const uint8_t *msg, size_t len,
                            wa_pb_prekey_t *out);

/* Extract text from a WAMessage (conversation / extendedTextMessage.text /
 * deviceSentMessage.message). Returns 0 and copies into out (NUL-terminated)
 * or -1 when the message carries no plain text. */
int wa_pb_decode_wamessage_text(const uint8_t *msg, size_t len, char *out,
                                size_t outcap);

#ifdef __cplusplus
}
#endif

#endif /* WA_PB_H */

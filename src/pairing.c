/* wa_pairing.c — pair-success handling (see wa_pairing.h). */
#include "wa_pairing.h"
#include "wa_crypto.h"
#include "wa_pb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const uint8_t WA_ADV_ACCOUNT_SIG_PREFIX[2] = { 6, 0 };
const uint8_t WA_ADV_DEVICE_SIG_PREFIX[2] = { 6, 1 };
const uint8_t WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX[2] = { 6, 5 };

static uint8_t *concat2(const uint8_t *a, size_t al, const uint8_t *b,
                        size_t bl, size_t *outlen) {
    uint8_t *o = malloc(al + bl);
    if (!o)
        return NULL;
    memcpy(o, a, al);
    memcpy(o + al, b, bl);
    *outlen = al + bl;
    return o;
}

int wa_pair_success(wa_creds_t *creds, const wa_node_t *stanza,
                    wa_node_t **reply_out) {
    const wa_node_t *ps, *dev_ident, *platform, *device, *biz;
    const char *jid, *lid, *biz_name, *plat_name, *msg_id;
    const uint8_t *hmac_details, *acc_details, *acc_key, *acc_sig;
    size_t hmac_details_len, acc_details_len, acc_key_len, acc_sig_len;
    const uint8_t *devsig_ignored;
    size_t devsig_ignored_len;
    uint8_t hmac[32], expect[32];
    int account_type;
    uint32_t key_index;
    int device_type;
    uint8_t *msg = NULL;
    size_t msglen = 0;
    uint8_t dev_sig[64];
    wa_pbw_t account_enc;
    wa_node_t *reply = NULL, *pds = NULL, *di = NULL;
    int rc = -1;

    *reply_out = NULL;
    if (!creds || !stanza)
        return -1;

    ps = wa_node_get_child(stanza, "pair-success");
    if (!ps)
        return -1;
    dev_ident = wa_node_get_child(ps, "device-identity");
    device = wa_node_get_child(ps, "device");
    if (!dev_ident || !device ||
        dev_ident->ctype != WA_CONTENT_BYTES)
        return -1;
    platform = wa_node_get_child(ps, "platform");
    biz = wa_node_get_child(ps, "biz");
    jid = wa_node_get_attr(device, "jid");
    lid = wa_node_get_attr(device, "lid");
    if (!jid || !lid)
        return -1;
    biz_name = biz ? wa_node_get_attr(biz, "name") : NULL;
    plat_name = platform ? wa_node_get_attr(platform, "name") : NULL;
    msg_id = wa_node_get_attr(stanza, "id");

    /* 1. HMAC over the signed-identity blob */
    if (wa_pb_decode_adv_hmac(dev_ident->content.bytes.data,
                              dev_ident->content.bytes.len, &hmac_details,
                              &hmac_details_len, hmac, &account_type))
        return -1;
    {
        const uint8_t *prefix = NULL;
        size_t prefix_len = 0;
        if (account_type == WA_ADV_HOSTED) {
            prefix = WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX;
            prefix_len = 2;
        }
        msg = concat2(prefix, prefix_len, hmac_details, hmac_details_len,
                      &msglen);
        if (!msg)
            return -1;
    }
    if (wa_hmac_sha256(creds->adv_secret, WA_ADV_LEN, msg, msglen, expect)) {
        free(msg);
        return -1;
    }
    free(msg);
    msg = NULL;
    if (memcmp(hmac, expect, 32) != 0)
        return -1; /* invalid account signature */

    /* 2. account signature by the phone's account key */
    if (wa_pb_decode_adv_account(hmac_details, hmac_details_len, &acc_details,
                                 &acc_details_len, &acc_key, &acc_key_len,
                                 &acc_sig, &acc_sig_len, &devsig_ignored,
                                 &devsig_ignored_len) ||
        acc_key_len != 32 || acc_sig_len != 64)
        return -1;
    if (wa_pb_decode_adv_device(acc_details, acc_details_len, &key_index,
                                &device_type))
        return -1;
    {
        const uint8_t *prefix = device_type == WA_ADV_HOSTED
                                    ? WA_ADV_HOSTED_ACCOUNT_SIG_PREFIX
                                    : WA_ADV_ACCOUNT_SIG_PREFIX;
        size_t need = 2 + acc_details_len + WA_KEY_LEN;
        msg = malloc(need);
        if (!msg)
            return -1;
        memcpy(msg, prefix, 2);
        memcpy(msg + 2, acc_details, acc_details_len);
        memcpy(msg + 2 + acc_details_len, creds->ident_pub, WA_KEY_LEN);
        msglen = need;
    }
    if (wa_xeddsa_verify(acc_key, msg, msglen, acc_sig)) {
        free(msg);
        return -1; /* failed to verify account signature */
    }
    free(msg);
    msg = NULL;

    /* 3. our device signature */
    {
        size_t need = 2 + acc_details_len + WA_KEY_LEN + 32;
        msg = malloc(need);
        if (!msg)
            return -1;
        memcpy(msg, WA_ADV_DEVICE_SIG_PREFIX, 2);
        memcpy(msg + 2, acc_details, acc_details_len);
        memcpy(msg + 2 + acc_details_len, creds->ident_pub, WA_KEY_LEN);
        memcpy(msg + 2 + acc_details_len + WA_KEY_LEN, acc_key, 32);
        msglen = need;
    }
    if (wa_xeddsa_sign(creds->ident_priv, msg, msglen, dev_sig)) {
        free(msg);
        return -1;
    }
    free(msg);

    /* 4. reply account blob WITHOUT the signature key */
    wa_pbw_init(&account_enc);
    if (wa_pb_encode_adv_account(acc_details, acc_details_len, NULL, 0,
                                 acc_sig, acc_sig_len, dev_sig,
                                 sizeof(dev_sig), &account_enc))
        return -1;

    reply = wa_node_new("iq");
    pds = wa_node_new("pair-device-sign");
    di = wa_node_new("device-identity");
    if (!reply || !pds || !di)
        goto fail;
    {
        char ki[16];
        snprintf(ki, sizeof(ki), "%u", key_index);
        if (wa_node_add_attr(reply, "to", "s.whatsapp.net") ||
            wa_node_add_attr(reply, "type", "result") ||
            (msg_id && wa_node_add_attr(reply, "id", msg_id)) ||
            wa_node_add_attr(di, "key-index", ki) ||
            wa_node_set_bytes(di, account_enc.data, account_enc.len) ||
            wa_node_add_child(pds, di) || wa_node_add_child(reply, pds))
            goto fail;
    }
    di = NULL; /* owned by tree now */
    pds = NULL;
    wa_pbw_free(&account_enc);

    /* 5. creds update */
    snprintf(creds->me_id, sizeof(creds->me_id), "%s", jid);
    snprintf(creds->me_lid, sizeof(creds->me_lid), "%s", lid);
    if (biz_name)
        snprintf(creds->me_name, sizeof(creds->me_name), "%s", biz_name);
    if (plat_name)
        snprintf(creds->platform, sizeof(creds->platform), "%s", plat_name);
    if (acc_details_len <= WA_ACCOUNT_DETAILS_MAX) {
        memcpy(creds->account.details, acc_details, acc_details_len);
        creds->account.details_len = acc_details_len;
        memcpy(creds->account.account_sig_key, acc_key, 32);
        memcpy(creds->account.account_sig, acc_sig, 64);
        memcpy(creds->account.device_sig, dev_sig, 64);
        creds->account.key_index = key_index;
        creds->account.present = 1;
    }
    /* TODO(Phase 5b): append createSignalIdentity(lid, accountSigKey) to a
     * persisted signal-identities store for session establishment. */

    *reply_out = reply;
    return 0;
fail:
    wa_pbw_free(&account_enc);
    wa_node_free(di);
    wa_node_free(pds);
    wa_node_free(reply);
    return rc;
}

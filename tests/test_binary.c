/* test_binary.c — WABinary codec roundtrips (no framework, assert-based). */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa_binary.h"

static int str_bytes_equal(const wa_node_t *s, const wa_node_t *b) {
    /* Wire-identical: a plain-ASCII string and its bytes both encode as
     * BINARY_8 (Baileys decodes BINARY_* content as Buffer). */
    size_t sl = strlen(s->content.str);
    return sl == b->content.bytes.len &&
           memcmp(s->content.str, b->content.bytes.data, sl) == 0;
}

static int nodes_equal(const wa_node_t *a, const wa_node_t *b) {
    if (strcmp(a->tag, b->tag) != 0 || a->n_attrs != b->n_attrs)
        return 0;
    for (size_t i = 0; i < a->n_attrs; i++)
        if (strcmp(a->attrs[i].key, b->attrs[i].key) != 0 ||
            strcmp(a->attrs[i].value, b->attrs[i].value) != 0)
            return 0;
    if (a->ctype != b->ctype) {
        /* string <-> bytes duality only (see above). */
        if (a->ctype == WA_CONTENT_STRING && b->ctype == WA_CONTENT_BYTES)
            return str_bytes_equal(a, b);
        if (a->ctype == WA_CONTENT_BYTES && b->ctype == WA_CONTENT_STRING)
            return str_bytes_equal(b, a);
        return 0;
    }
    if (a->ctype == WA_CONTENT_STRING)
        return strcmp(a->content.str, b->content.str) == 0;
    if (a->ctype == WA_CONTENT_BYTES)
        return a->content.bytes.len == b->content.bytes.len &&
               memcmp(a->content.bytes.data, b->content.bytes.data,
                      a->content.bytes.len) == 0;
    if (a->ctype == WA_CONTENT_CHILDREN) {
        if (a->content.children.len != b->content.children.len)
            return 0;
        for (size_t i = 0; i < a->content.children.len; i++)
            if (!nodes_equal(a->content.children.items[i],
                             b->content.children.items[i]))
                return 0;
    }
    return 1;
}

static void roundtrip(wa_node_t *n, const char *name) {
    wa_buf_t buf;
    assert(wa_encode_node(n, &buf) == 0);
    assert(buf.len > 1 && buf.data[0] == 0); /* flags byte */
    wa_node_t *back = NULL;
    size_t consumed = 0;
    assert(wa_decode_node(buf.data, buf.len, &back, &consumed) == 0);
    assert(consumed == buf.len);
    if (!nodes_equal(n, back)) {
        char *a = wa_node_to_string(n);
        char *b = wa_node_to_string(back);
        fprintf(stderr, "MISMATCH [%s]:\n--- want ---\n%s--- got ---\n%s", name,
                a, b);
        free(a);
        free(b);
        assert(0);
    }
    printf("ok: %s (%zu bytes)\n", name, buf.len);
    wa_node_free(back);
    wa_buf_free(&buf);
}

int main(void) {
    /* 1. iq stanza with attrs + string child (token-heavy path). */
    wa_node_t *iq = wa_node_new("iq");
    assert(iq);
    assert(wa_node_add_attr(iq, "to", "s.whatsapp.net") == 0);
    assert(wa_node_add_attr(iq, "type", "get") == 0);
    assert(wa_node_add_attr(iq, "xmlns", "encrypt") == 0);
    assert(wa_node_add_attr(iq, "id", "cwa.0") == 0);
    wa_node_t *count = wa_node_new("count");
    assert(wa_node_add_attr(count, "value", "100") == 0);
    assert(wa_node_add_child(iq, count) == 0);
    roundtrip(iq, "iq/get/encrypt");
    wa_node_free(iq);

    /* 2. JID values: plain PN, device JID (AD-JID), LID. */
    wa_node_t *msg = wa_node_new("message");
    assert(wa_node_add_attr(msg, "from", "15551234567@s.whatsapp.net") == 0);
    assert(wa_node_add_attr(msg, "to", "15551234567:5@s.whatsapp.net") == 0);
    assert(wa_node_add_attr(msg, "participant", "12345@lid") == 0);
    assert(wa_node_set_string(msg, "hello") == 0);
    roundtrip(msg, "message/jids");
    wa_node_free(msg);

    /* 3. binary bytes content + raw (untokenized) strings. */
    wa_node_t *bin = wa_node_new("pair-device");
    assert(wa_node_add_attr(bin, "custom-attr-zzz", "custom-value-yyy") == 0);
    uint8_t blob[] = { 0x00, 0xff, 0x01, 0x02, 0xfd, 0x10 };
    assert(wa_node_set_bytes(bin, blob, sizeof(blob)) == 0);
    roundtrip(bin, "bytes/raw-strings");
    wa_node_free(bin);

    /* 4. packed nibble + hex strings. */
    wa_node_t *pk = wa_node_new("test");
    assert(wa_node_add_attr(pk, "nibble", "123-45.67") == 0);
    assert(wa_node_add_attr(pk, "hex", "ABCDEF0123456789") == 0);
    roundtrip(pk, "packed-nibble-hex");
    wa_node_free(pk);

    /* 5. 300-byte blob forces BINARY_20 length prefix. */
    wa_node_t *big = wa_node_new("blob");
    uint8_t large[300];
    for (int i = 0; i < 300; i++)
        large[i] = (uint8_t)i;
    assert(wa_node_set_bytes(big, large, sizeof(large)) == 0);
    roundtrip(big, "binary-20-300B");
    wa_node_free(big);

    /* 6. empty node, no attrs/content. */
    wa_node_t *empty = wa_node_new("ping");
    roundtrip(empty, "empty-node");
    wa_node_free(empty);

    printf("all binary tests passed\n");
    return 0;
}

/* wa_binary.h — WhatsApp binary-node (WABinary) codec.
 *
 * Ports Baileys src/WABinary/encode.ts + decode.ts:
 *   node = { tag, attrs, content } where content is none | string |
 *   bytes | child-node list. Wire format uses token dictionaries,
 *   packed nibble/hex strings, JID-pair / AD-JID forms and BINARY_8/20/32
 *   length prefixes.
 */
#ifndef WA_BINARY_H
#define WA_BINARY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol tags (Baileys TAGS constants). */
enum {
    WA_TAG_LIST_EMPTY = 0,
    WA_TAG_DICTIONARY_0 = 236,
    WA_TAG_DICTIONARY_1 = 237,
    WA_TAG_DICTIONARY_2 = 238,
    WA_TAG_DICTIONARY_3 = 239,
    WA_TAG_INTEROP_JID = 245,
    WA_TAG_FB_JID = 246,
    WA_TAG_AD_JID = 247,
    WA_TAG_LIST_8 = 248,
    WA_TAG_LIST_16 = 249,
    WA_TAG_JID_PAIR = 250,
    WA_TAG_HEX_8 = 251,
    WA_TAG_BINARY_8 = 252,
    WA_TAG_BINARY_20 = 253,
    WA_TAG_BINARY_32 = 254,
    WA_TAG_NIBBLE_8 = 255,
    WA_PACKED_MAX = 127
};

typedef struct {
    char *key;
    char *value;
} wa_attr_t;

typedef enum {
    WA_CONTENT_NONE = 0,
    WA_CONTENT_STRING,
    WA_CONTENT_BYTES,
    WA_CONTENT_CHILDREN
} wa_content_type_t;

typedef struct wa_node {
    char *tag;
    wa_attr_t *attrs;
    size_t n_attrs;
    wa_content_type_t ctype;
    union {
        char *str; /* WA_CONTENT_STRING */
        struct {
            uint8_t *data;
            size_t len;
        } bytes; /* WA_CONTENT_BYTES */
        struct {
            struct wa_node **items;
            size_t len;
        } children; /* WA_CONTENT_CHILDREN */
    } content;
} wa_node_t;

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} wa_buf_t;

void wa_buf_init(wa_buf_t *b);
void wa_buf_free(wa_buf_t *b);
int wa_buf_reserve(wa_buf_t *b, size_t extra);

/* Encode: first byte is 0 (flags, matches Baileys buffer=[0]). */
int wa_encode_node(const wa_node_t *node, wa_buf_t *out);

/* Decode one node from data[0..len). *consumed = bytes used. */
int wa_decode_node(const uint8_t *data, size_t len, wa_node_t **out, size_t *consumed);

/* Constructors / helpers (all strings are copied). */
wa_node_t *wa_node_new(const char *tag);
void wa_node_free(wa_node_t *n);
int wa_node_add_attr(wa_node_t *n, const char *key, const char *value);
int wa_node_set_string(wa_node_t *n, const char *s);
int wa_node_set_bytes(wa_node_t *n, const uint8_t *data, size_t len);
int wa_node_add_child(wa_node_t *parent, wa_node_t *child); /* takes ownership */
const char *wa_node_get_attr(const wa_node_t *n, const char *key);
wa_node_t *wa_node_get_child(const wa_node_t *n, const char *tag);

/* Debug helper: malloc'd XML-ish string, caller frees. */
char *wa_node_to_string(const wa_node_t *n);

#ifdef __cplusplus
}
#endif

#endif /* WA_BINARY_H */

/* wa_binary.c — WABinary encode/decode.
 * Mirrors Baileys src/WABinary/encode.ts + decode.ts (pinned commit, see
 * tools/gen_tokens.py). Compression (zlib flag 0x02) is detected and
 * reported; inflate support lands with the socket layer (Phase 3).
 */
#define _POSIX_C_SOURCE 200809L
#include "wa_binary.h"
#include "wa_tokens.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* ------------------------------------------------------------------ */
/* buffer                                                              */
/* ------------------------------------------------------------------ */

void wa_buf_init(wa_buf_t *b) {
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void wa_buf_free(wa_buf_t *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

int wa_buf_reserve(wa_buf_t *b, size_t extra) {
    if (b->len + extra <= b->cap)
        return 0;
    size_t ncap = b->cap ? b->cap * 2 : 256;
    while (ncap < b->len + extra)
        ncap *= 2;
    uint8_t *nd = realloc(b->data, ncap);
    if (!nd)
        return -1;
    b->data = nd;
    b->cap = ncap;
    return 0;
}

static int push_byte(wa_buf_t *b, uint8_t v) {
    if (wa_buf_reserve(b, 1))
        return -1;
    b->data[b->len++] = v;
    return 0;
}

static int push_n(wa_buf_t *b, const uint8_t *p, size_t n) {
    if (wa_buf_reserve(b, n))
        return -1;
    memcpy(b->data + b->len, p, n);
    b->len += n;
    return 0;
}

/* ------------------------------------------------------------------ */
/* node helpers                                                        */
/* ------------------------------------------------------------------ */

wa_node_t *wa_node_new(const char *tag) {
    if (!tag)
        return NULL;
    wa_node_t *n = calloc(1, sizeof(*n));
    if (!n)
        return NULL;
    n->tag = strdup(tag);
    if (!n->tag) {
        free(n);
        return NULL;
    }
    return n;
}

void wa_node_free(wa_node_t *n) {
    if (!n)
        return;
    free(n->tag);
    for (size_t i = 0; i < n->n_attrs; i++) {
        free(n->attrs[i].key);
        free(n->attrs[i].value);
    }
    free(n->attrs);
    if (n->ctype == WA_CONTENT_STRING)
        free(n->content.str);
    else if (n->ctype == WA_CONTENT_BYTES)
        free(n->content.bytes.data);
    else if (n->ctype == WA_CONTENT_CHILDREN) {
        for (size_t i = 0; i < n->content.children.len; i++)
            wa_node_free(n->content.children.items[i]);
        free(n->content.children.items);
    }
    free(n);
}

int wa_node_add_attr(wa_node_t *n, const char *key, const char *value) {
    if (!n || !key || !value)
        return -1;
    wa_attr_t *na = realloc(n->attrs, (n->n_attrs + 1) * sizeof(*na));
    if (!na)
        return -1;
    n->attrs = na;
    n->attrs[n->n_attrs].key = strdup(key);
    n->attrs[n->n_attrs].value = strdup(value);
    if (!n->attrs[n->n_attrs].key || !n->attrs[n->n_attrs].value) {
        free(n->attrs[n->n_attrs].key);
        free(n->attrs[n->n_attrs].value);
        return -1;
    }
    n->n_attrs++;
    return 0;
}

static void wa_content_clear(wa_node_t *n) {
    if (n->ctype == WA_CONTENT_STRING)
        free(n->content.str);
    else if (n->ctype == WA_CONTENT_BYTES)
        free(n->content.bytes.data);
    else if (n->ctype == WA_CONTENT_CHILDREN) {
        for (size_t i = 0; i < n->content.children.len; i++)
            wa_node_free(n->content.children.items[i]);
        free(n->content.children.items);
    }
    memset(&n->content, 0, sizeof(n->content));
    n->ctype = WA_CONTENT_NONE;
}

int wa_node_set_string(wa_node_t *n, const char *s) {
    if (!n || !s)
        return -1;
    wa_content_clear(n);
    n->content.str = strdup(s);
    if (!n->content.str)
        return -1;
    n->ctype = WA_CONTENT_STRING;
    return 0;
}

int wa_node_set_bytes(wa_node_t *n, const uint8_t *data, size_t len) {
    if (!n || (!data && len))
        return -1;
    wa_content_clear(n);
    n->content.bytes.data = malloc(len ? len : 1);
    if (!n->content.bytes.data)
        return -1;
    if (len)
        memcpy(n->content.bytes.data, data, len);
    n->content.bytes.len = len;
    n->ctype = WA_CONTENT_BYTES;
    return 0;
}

int wa_node_add_child(wa_node_t *parent, wa_node_t *child) {
    if (!parent || !child)
        return -1;
    if (parent->ctype == WA_CONTENT_STRING || parent->ctype == WA_CONTENT_BYTES)
        return -1;
    parent->ctype = WA_CONTENT_CHILDREN;
    size_t nl = parent->content.children.len + 1;
    wa_node_t **ni =
        realloc(parent->content.children.items, nl * sizeof(*ni));
    if (!ni)
        return -1;
    parent->content.children.items = ni;
    parent->content.children.items[parent->content.children.len] = child;
    parent->content.children.len = nl;
    return 0;
}

const char *wa_node_get_attr(const wa_node_t *n, const char *key) {
    if (!n || !key)
        return NULL;
    for (size_t i = 0; i < n->n_attrs; i++)
        if (strcmp(n->attrs[i].key, key) == 0)
            return n->attrs[i].value;
    return NULL;
}

wa_node_t *wa_node_get_child(const wa_node_t *n, const char *tag) {
    if (!n || !tag || n->ctype != WA_CONTENT_CHILDREN)
        return NULL;
    for (size_t i = 0; i < n->content.children.len; i++)
        if (strcmp(n->content.children.items[i]->tag, tag) == 0)
            return n->content.children.items[i];
    return NULL;
}

/* ------------------------------------------------------------------ */
/* encode helpers                                                      */
/* ------------------------------------------------------------------ */

static int push_u16(wa_buf_t *b, unsigned v) {
    uint8_t tmp[2] = { (uint8_t)((v >> 8) & 0xff), (uint8_t)(v & 0xff) };
    return push_n(b, tmp, 2);
}

/* BINARY_8/20/32 length prefix. */
static int write_byte_length(wa_buf_t *b, size_t len) {
    if (len >= 256 && len < (1u << 20)) {
        if (push_byte(b, WA_TAG_BINARY_20))
            return -1;
        uint8_t tmp[3] = { (uint8_t)((len >> 16) & 0x0f),
                           (uint8_t)((len >> 8) & 0xff),
                           (uint8_t)(len & 0xff) };
        return push_n(b, tmp, 3);
    }
    if (len >= (1u << 20)) {
        if (push_byte(b, WA_TAG_BINARY_32))
            return -1;
        uint8_t tmp[4] = { (uint8_t)((len >> 24) & 0xff),
                           (uint8_t)((len >> 16) & 0xff),
                           (uint8_t)((len >> 8) & 0xff),
                           (uint8_t)(len & 0xff) };
        return push_n(b, tmp, 4);
    }
    if (push_byte(b, WA_TAG_BINARY_8))
        return -1;
    return push_byte(b, (uint8_t)len);
}

static int write_string_raw(wa_buf_t *b, const char *s, size_t slen) {
    if (write_byte_length(b, slen))
        return -1;
    return push_n(b, (const uint8_t *)s, slen);
}

static int is_nibble_str(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n > WA_PACKED_MAX)
        return 0;
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || c == '-' || c == '.'))
            return 0;
    }
    return 1;
}

static int is_hex_str(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n > WA_PACKED_MAX)
        return 0;
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))
            return 0;
    }
    return 1;
}

static int pack_nibble_char(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c == '-')
        return 10;
    if (c == '.')
        return 11;
    if (c == '\0')
        return 15;
    return -1;
}

static int pack_hex_char(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return 10 + c - 'A';
    if (c >= 'a' && c <= 'f')
        return 10 + c - 'a';
    if (c == '\0')
        return 15;
    return -1;
}

/* JID split: "user[:device]@server". Returns 0 if '@' present. */
static int jid_split(const char *s, const char **user, size_t *user_len,
                     int *device, const char **server) {
    const char *at = strchr(s, '@');
    if (!at)
        return -1;
    const char *colon = memchr(s, ':', (size_t)(at - s));
    if (colon) {
        *user = s;
        *user_len = (size_t)(colon - s);
        /* device part must be numeric for AD-JID; else not a JID */
        char *end = NULL;
        long d = strtol(colon + 1, &end, 10);
        if (end != at || d < 0 || d > 255)
            return -1;
        *device = (int)d;
    } else {
        *user = s;
        *user_len = (size_t)(at - s);
        *device = -1;
    }
    *server = at + 1;
    return **server ? 0 : -1;
}

static int wa_domain_type(const char *server) {
    if (strcmp(server, "lid") == 0)
        return 1;
    if (strcmp(server, "hosted") == 0)
        return 128;
    if (strcmp(server, "hosted.lid") == 0)
        return 129;
    return 0;
}

static int write_string(wa_buf_t *b, const char *s);

static int write_jid(wa_buf_t *b, const char *user, size_t user_len,
                     int device, const char *server) {
    char ubuf[256];
    if (user_len >= sizeof(ubuf))
        return -1;
    memcpy(ubuf, user, user_len);
    ubuf[user_len] = '\0';
    if (device >= 0) {
        if (push_byte(b, WA_TAG_AD_JID) || push_byte(b, (uint8_t)wa_domain_type(server)) ||
            push_byte(b, (uint8_t)device))
            return -1;
        return write_string(b, ubuf);
    }
    if (push_byte(b, WA_TAG_JID_PAIR))
        return -1;
    if (user_len == 0) {
        if (push_byte(b, WA_TAG_LIST_EMPTY))
            return -1;
    } else if (write_string(b, ubuf)) {
        return -1;
    }
    return write_string(b, server);
}

static int write_packed(wa_buf_t *b, const char *s, int hex) {
    size_t n = strlen(s);
    if (push_byte(b, hex ? WA_TAG_HEX_8 : WA_TAG_NIBBLE_8))
        return -1;
    size_t rounded = (n + 1) / 2;
    uint8_t lenbyte = (uint8_t)rounded;
    if (n % 2 != 0)
        lenbyte |= 128;
    if (push_byte(b, lenbyte))
        return -1;
    for (size_t i = 0; i + 1 < n; i += 2) {
        int hi = hex ? pack_hex_char(s[i]) : pack_nibble_char(s[i]);
        int lo = hex ? pack_hex_char(s[i + 1]) : pack_nibble_char(s[i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        if (push_byte(b, (uint8_t)((hi << 4) | lo)))
            return -1;
    }
    if (n % 2 != 0) {
        int hi = hex ? pack_hex_char(s[n - 1]) : pack_nibble_char(s[n - 1]);
        if (hi < 0)
            return -1;
        int lo = hex ? pack_hex_char('\0') : pack_nibble_char('\0');
        if (push_byte(b, (uint8_t)((hi << 4) | lo)))
            return -1;
    }
    return 0;
}

static int write_string(wa_buf_t *b, const char *s) {
    if (!s) /* Baileys: undefined -> LIST_EMPTY */
        return push_byte(b, WA_TAG_LIST_EMPTY);
    if (!*s) /* empty string -> raw zero-length */
        return write_string_raw(b, s, 0);
    int dict, index;
    if (wa_token_lookup(s, &dict, &index)) {
        if (dict >= 0) {
            if (push_byte(b, (uint8_t)(WA_TAG_DICTIONARY_0 + dict)))
                return -1;
        }
        return push_byte(b, (uint8_t)index);
    }
    if (is_nibble_str(s))
        return write_packed(b, s, 0);
    if (is_hex_str(s))
        return write_packed(b, s, 1);
    const char *user, *server;
    size_t user_len;
    int device;
    if (jid_split(s, &user, &user_len, &device, &server) == 0)
        return write_jid(b, user, user_len, device, server);
    return write_string_raw(b, s, strlen(s));
}

static int write_list_start(wa_buf_t *b, size_t size) {
    if (size == 0)
        return push_byte(b, WA_TAG_LIST_EMPTY);
    if (size < 256) {
        if (push_byte(b, WA_TAG_LIST_8))
            return -1;
        return push_byte(b, (uint8_t)size);
    }
    if (push_byte(b, WA_TAG_LIST_16))
        return -1;
    return push_u16(b, (unsigned)size);
}

static int encode_inner(const wa_node_t *node, wa_buf_t *b) {
    if (!node || !node->tag)
        return -1;
    size_t list_size = 2 * node->n_attrs + 1 + (node->ctype != WA_CONTENT_NONE ? 1 : 0);
    if (write_list_start(b, list_size))
        return -1;
    if (write_string(b, node->tag))
        return -1;
    for (size_t i = 0; i < node->n_attrs; i++) {
        if (write_string(b, node->attrs[i].key))
            return -1;
        if (write_string(b, node->attrs[i].value))
            return -1;
    }
    switch (node->ctype) {
    case WA_CONTENT_NONE:
        break;
    case WA_CONTENT_STRING:
        if (write_string(b, node->content.str))
            return -1;
        break;
    case WA_CONTENT_BYTES:
        if (write_byte_length(b, node->content.bytes.len))
            return -1;
        if (push_n(b, node->content.bytes.data, node->content.bytes.len))
            return -1;
        break;
    case WA_CONTENT_CHILDREN:
        if (write_list_start(b, node->content.children.len))
            return -1;
        for (size_t i = 0; i < node->content.children.len; i++)
            if (encode_inner(node->content.children.items[i], b))
                return -1;
        break;
    }
    return 0;
}

int wa_encode_node(const wa_node_t *node, wa_buf_t *out) {
    if (!node || !out)
        return -1;
    wa_buf_init(out);
    if (push_byte(out, 0)) { /* flags byte: uncompressed */
        wa_buf_free(out);
        return -1;
    }
    if (encode_inner(node, out)) {
        wa_buf_free(out);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* decode                                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    const uint8_t *p;
    size_t len;
    size_t pos;
} reader_t;

static int rd_check(reader_t *r, size_t n) {
    return r->pos + n <= r->len ? 0 : -1;
}

static int rd_byte(reader_t *r, uint8_t *out) {
    if (rd_check(r, 1))
        return -1;
    *out = r->p[r->pos++];
    return 0;
}

/* Forward decls */
static int rd_string(reader_t *r, uint8_t tag, char **out);
static int rd_node(reader_t *r, wa_node_t **out);

static char *dup_n(const char *s, size_t n) {
    char *d = malloc(n + 1);
    if (!d)
        return NULL;
    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

static int rd_bytes(reader_t *r, size_t n, const uint8_t **ptr) {
    if (rd_check(r, n))
        return -1;
    *ptr = r->p + r->pos;
    r->pos += n;
    return 0;
}

static int unpack_nibble_val(int v, char *out) {
    if (v >= 0 && v <= 9) {
        *out = (char)('0' + v);
        return 0;
    }
    if (v == 10) {
        *out = '-';
        return 0;
    }
    if (v == 11) {
        *out = '.';
        return 0;
    }
    if (v == 15) {
        *out = '\0'; /* padding sentinel */
        return 0;
    }
    return -1;
}

static int unpack_hex_val(int v, char *out) {
    if (v >= 0 && v <= 9) {
        *out = (char)('0' + v);
        return 0;
    }
    if (v >= 10 && v <= 15) {
        *out = (char)('A' + v - 10);
        return 0;
    }
    return -1;
}

static int rd_packed(reader_t *r, uint8_t tag, char **out) {
    uint8_t start;
    if (rd_byte(r, &start))
        return -1;
    size_t count = start & 127;
    /* worst case 2 chars/byte */
    char *buf = malloc(count * 2 + 1);
    if (!buf)
        return -1;
    size_t n = 0;
    for (size_t i = 0; i < count; i++) {
        uint8_t cur;
        if (rd_byte(r, &cur)) {
            free(buf);
            return -1;
        }
        char hi, lo;
        int ok;
        if (tag == WA_TAG_NIBBLE_8)
            ok = unpack_nibble_val((cur & 0xf0) >> 4, &hi) == 0 &&
                 unpack_nibble_val(cur & 0x0f, &lo) == 0;
        else
            ok = unpack_hex_val((cur & 0xf0) >> 4, &hi) == 0 &&
                 unpack_hex_val(cur & 0x0f, &lo) == 0;
        if (!ok) {
            free(buf);
            return -1;
        }
        buf[n++] = hi;
        buf[n++] = lo;
    }
    if (start >> 7)
        n--; /* trailing padding */
    buf[n] = '\0';
    *out = buf;
    return 0;
}

static const char *server_from_domain(int dt) {
    if (dt == 1)
        return "lid";
    if (dt == 128)
        return "hosted";
    if (dt == 129)
        return "hosted.lid";
    return "s.whatsapp.net";
}

static int rd_jid_pair(reader_t *r, char **out) {
    uint8_t t1, t2;
    char *u = NULL, *s = NULL;
    if (rd_byte(r, &t1) || rd_string(r, t1, &u))
        return -1;
    if (rd_byte(r, &t2) || rd_string(r, t2, &s)) {
        free(u);
        return -1;
    }
    if (!*s) {
        free(u);
        free(s);
        return -1;
    }
    size_t n = strlen(u) + 1 + strlen(s) + 1;
    char *jid = malloc(n);
    if (!jid) {
        free(u);
        free(s);
        return -1;
    }
    snprintf(jid, n, "%s@%s", u, s);
    free(u);
    free(s);
    *out = jid;
    return 0;
}

static int rd_ad_jid(reader_t *r, char **out) {
    uint8_t dt, dev, tu;
    char *u = NULL;
    if (rd_byte(r, &dt) || rd_byte(r, &dev) || rd_byte(r, &tu) ||
        rd_string(r, tu, &u))
        return -1;
    const char *server = server_from_domain(dt);
    size_t n = strlen(u) + 8 + strlen(server) + 1;
    char *jid = malloc(n);
    if (!jid) {
        free(u);
        return -1;
    }
    snprintf(jid, n, "%s:%u@%s", u, dev, server);
    free(u);
    *out = jid;
    return 0;
}

static int rd_fb_jid(reader_t *r, char **out) {
    uint8_t tu, ts;
    char *u = NULL, *s = NULL;
    const uint8_t *dp;
    if (rd_byte(r, &tu) || rd_string(r, tu, &u))
        return -1;
    if (rd_bytes(r, 2, &dp)) {
        free(u);
        return -1;
    }
    unsigned dev = ((unsigned)dp[0] << 8) | dp[1];
    if (rd_byte(r, &ts) || rd_string(r, ts, &s)) {
        free(u);
        return -1;
    }
    size_t n = strlen(u) + 8 + strlen(s) + 1;
    char *jid = malloc(n);
    if (!jid) {
        free(u);
        free(s);
        return -1;
    }
    snprintf(jid, n, "%s:%u@%s", u, dev, s);
    free(u);
    free(s);
    *out = jid;
    return 0;
}

static int rd_string(reader_t *r, uint8_t tag, char **out) {
    if (tag >= 1 && tag < WA_SINGLE_TOKENS_LEN) {
        *out = strdup(wa_token_string(-1, tag));
        return *out ? 0 : -1;
    }
    switch (tag) {
    case WA_TAG_DICTIONARY_0:
    case WA_TAG_DICTIONARY_1:
    case WA_TAG_DICTIONARY_2:
    case WA_TAG_DICTIONARY_3: {
        uint8_t idx;
        if (rd_byte(r, &idx))
            return -1;
        *out = strdup(wa_token_string(tag - WA_TAG_DICTIONARY_0, idx));
        return *out ? 0 : -1;
    }
    case WA_TAG_LIST_EMPTY:
        *out = strdup("");
        return *out ? 0 : -1;
    case WA_TAG_BINARY_8: {
        uint8_t n;
        const uint8_t *ptr;
        if (rd_byte(r, &n) || rd_bytes(r, n, &ptr))
            return -1;
        *out = dup_n((const char *)ptr, n);
        return *out ? 0 : -1;
    }
    case WA_TAG_BINARY_20: {
        const uint8_t *lp;
        if (rd_bytes(r, 3, &lp))
            return -1;
        size_t n = ((size_t)(lp[0] & 15) << 16) | ((size_t)lp[1] << 8) | lp[2];
        const uint8_t *ptr;
        if (rd_bytes(r, n, &ptr))
            return -1;
        *out = dup_n((const char *)ptr, n);
        return *out ? 0 : -1;
    }
    case WA_TAG_BINARY_32: {
        const uint8_t *lp;
        if (rd_bytes(r, 4, &lp))
            return -1;
        size_t n = ((size_t)lp[0] << 24) | ((size_t)lp[1] << 16) |
                   ((size_t)lp[2] << 8) | lp[3];
        const uint8_t *ptr;
        if (rd_bytes(r, n, &ptr))
            return -1;
        *out = dup_n((const char *)ptr, n);
        return *out ? 0 : -1;
    }
    case WA_TAG_JID_PAIR:
        return rd_jid_pair(r, out);
    case WA_TAG_AD_JID:
        return rd_ad_jid(r, out);
    case WA_TAG_FB_JID:
        return rd_fb_jid(r, out);
    case WA_TAG_HEX_8:
    case WA_TAG_NIBBLE_8:
        return rd_packed(r, tag, out);
    default:
        return -1;
    }
}

static int rd_list_size(reader_t *r, uint8_t tag, size_t *out) {
    if (tag == WA_TAG_LIST_EMPTY) {
        *out = 0;
        return 0;
    }
    if (tag == WA_TAG_LIST_8) {
        uint8_t n;
        if (rd_byte(r, &n))
            return -1;
        *out = n;
        return 0;
    }
    if (tag == WA_TAG_LIST_16) {
        const uint8_t *lp;
        if (rd_bytes(r, 2, &lp))
            return -1;
        *out = ((size_t)lp[0] << 8) | lp[1];
        return 0;
    }
    return -1;
}

static int is_list_tag(uint8_t t) {
    return t == WA_TAG_LIST_EMPTY || t == WA_TAG_LIST_8 || t == WA_TAG_LIST_16;
}

static int rd_node(reader_t *r, wa_node_t **out) {
    uint8_t lt, ht;
    size_t list_size;
    char *header = NULL;
    if (rd_byte(r, &lt) || rd_list_size(r, lt, &list_size))
        return -1;
    if (rd_byte(r, &ht) || rd_string(r, ht, &header))
        return -1;
    if (list_size == 0 || !header || !*header) {
        free(header);
        return -1;
    }
    wa_node_t *n = wa_node_new(header);
    free(header);
    if (!n)
        return -1;
    size_t n_attr_pairs = (list_size - 1) >> 1;
    for (size_t i = 0; i < n_attr_pairs; i++) {
        uint8_t kt, vt;
        char *k = NULL, *v = NULL;
        if (rd_byte(r, &kt) || rd_string(r, kt, &k)) {
            wa_node_free(n);
            return -1;
        }
        if (rd_byte(r, &vt) || rd_string(r, vt, &v)) {
            free(k);
            wa_node_free(n);
            return -1;
        }
        if (wa_node_add_attr(n, k, v)) {
            free(k);
            free(v);
            wa_node_free(n);
            return -1;
        }
        free(k);
        free(v);
    }
    if (list_size % 2 == 0) {
        uint8_t ct;
        if (rd_byte(r, &ct)) {
            wa_node_free(n);
            return -1;
        }
        if (is_list_tag(ct)) {
            size_t cn;
            if (rd_list_size(r, ct, &cn)) {
                wa_node_free(n);
                return -1;
            }
            n->ctype = WA_CONTENT_CHILDREN;
            for (size_t i = 0; i < cn; i++) {
                wa_node_t *child = NULL;
                if (rd_node(r, &child)) {
                    wa_node_free(n);
                    return -1;
                }
                /* steal ownership without tripping the string/bytes guard */
                size_t nl = n->content.children.len + 1;
                wa_node_t **ni = realloc(n->content.children.items,
                                        nl * sizeof(*ni));
                if (!ni) {
                    wa_node_free(child);
                    wa_node_free(n);
                    return -1;
                }
                n->content.children.items = ni;
                n->content.children.items[n->content.children.len] = child;
                n->content.children.len = nl;
            }
        } else if (ct == WA_TAG_BINARY_8 || ct == WA_TAG_BINARY_20 ||
                   ct == WA_TAG_BINARY_32) {
            size_t blen = 0;
            if (ct == WA_TAG_BINARY_8) {
                uint8_t b;
                if (rd_byte(r, &b)) {
                    wa_node_free(n);
                    return -1;
                }
                blen = b;
            } else if (ct == WA_TAG_BINARY_20) {
                const uint8_t *lp;
                if (rd_bytes(r, 3, &lp)) {
                    wa_node_free(n);
                    return -1;
                }
                blen = ((size_t)(lp[0] & 15) << 16) | ((size_t)lp[1] << 8) | lp[2];
            } else {
                const uint8_t *lp;
                if (rd_bytes(r, 4, &lp)) {
                    wa_node_free(n);
                    return -1;
                }
                blen = ((size_t)lp[0] << 24) | ((size_t)lp[1] << 16) |
                       ((size_t)lp[2] << 8) | lp[3];
            }
            const uint8_t *ptr;
            if (rd_bytes(r, blen, &ptr)) {
                wa_node_free(n);
                return -1;
            }
            if (wa_node_set_bytes(n, ptr, blen)) {
                wa_node_free(n);
                return -1;
            }
        } else {
            char *s = NULL;
            if (rd_string(r, ct, &s)) {
                wa_node_free(n);
                return -1;
            }
            n->ctype = WA_CONTENT_STRING;
            n->content.str = s;
        }
    }
    *out = n;
    return 0;
}

/* Inflate zlib-wrapped deflate (Baileys decompressingIfRequired). */
static int wa_inflate(const uint8_t *in, size_t ilen, uint8_t **out,
                      size_t *olen) {
    z_stream zs;
    size_t cap = ilen * 3 + 64;
    uint8_t *buf = malloc(cap);
    int rc;
    if (!buf)
        return -1;
    memset(&zs, 0, sizeof(zs));
    zs.next_in = (Bytef *)in;
    zs.avail_in = (uInt)ilen;
    if (inflateInit(&zs) != Z_OK) {
        free(buf);
        return -1;
    }
    for (;;) {
        if (zs.total_out >= cap) {
            cap *= 2;
            uint8_t *nb = realloc(buf, cap);
            if (!nb) {
                inflateEnd(&zs);
                free(buf);
                return -1;
            }
            buf = nb;
        }
        zs.next_out = buf + zs.total_out;
        zs.avail_out = (uInt)(cap - zs.total_out);
        rc = inflate(&zs, Z_NO_FLUSH);
        if (rc == Z_STREAM_END)
            break;
        if (rc != Z_OK) {
            inflateEnd(&zs);
            free(buf);
            return -1;
        }
        if (zs.avail_in == 0 && zs.avail_out > 0)
            break;
    }
    inflateEnd(&zs);
    *out = buf;
    *olen = zs.total_out;
    return 0;
}

int wa_decode_node(const uint8_t *data, size_t len, wa_node_t **out,
                   size_t *consumed) {
    if (!data || len < 1 || !out)
        return -1;
    if (data[0] & 2) {
        /* Compressed frame: inflate rest, then decode (consumes all). */
        uint8_t *dec = NULL;
        size_t dlen = 0;
        reader_t r;
        wa_node_t *n = NULL;
        if (wa_inflate(data + 1, len - 1, &dec, &dlen))
            return -1;
        r.p = dec;
        r.len = dlen;
        r.pos = 0;
        if (rd_node(&r, &n)) {
            free(dec);
            return -1;
        }
        free(dec);
        *out = n;
        if (consumed)
            *consumed = len;
        return 0;
    }
    reader_t r = { data + 1, len - 1, 0 };
    wa_node_t *n = NULL;
    if (rd_node(&r, &n))
        return -1;
    *out = n;
    if (consumed)
        *consumed = r.pos + 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* debug                                                               */
/* ------------------------------------------------------------------ */

static void str_append(char **dst, size_t *len, const char *s) {
    size_t sl = strlen(s);
    char *nd = realloc(*dst, *len + sl + 1);
    if (!nd)
        return;
    memcpy(nd + *len, s, sl + 1);
    *dst = nd;
    *len += sl;
}

static void node_str(const wa_node_t *n, char **dst, size_t *len, int depth) {
    char tmp[256];
    for (int i = 0; i < depth; i++)
        str_append(dst, len, "  ");
    snprintf(tmp, sizeof(tmp), "<%s", n->tag);
    str_append(dst, len, tmp);
    for (size_t i = 0; i < n->n_attrs; i++) {
        snprintf(tmp, sizeof(tmp), " %s='%s'", n->attrs[i].key, n->attrs[i].value);
        str_append(dst, len, tmp);
    }
    if (n->ctype == WA_CONTENT_NONE) {
        str_append(dst, len, "/>\n");
        return;
    }
    str_append(dst, len, ">");
    if (n->ctype == WA_CONTENT_STRING) {
        str_append(dst, len, n->content.str);
        snprintf(tmp, sizeof(tmp), "</%s>\n", n->tag);
        str_append(dst, len, tmp);
    } else if (n->ctype == WA_CONTENT_BYTES) {
        snprintf(tmp, sizeof(tmp), "[%zu bytes]</%s>\n",
                 n->content.bytes.len, n->tag);
        str_append(dst, len, tmp);
    } else {
        str_append(dst, len, "\n");
        for (size_t i = 0; i < n->content.children.len; i++)
            node_str(n->content.children.items[i], dst, len, depth + 1);
        for (int i = 0; i < depth; i++)
            str_append(dst, len, "  ");
        snprintf(tmp, sizeof(tmp), "</%s>\n", n->tag);
        str_append(dst, len, tmp);
    }
}

char *wa_node_to_string(const wa_node_t *n) {
    if (!n)
        return NULL;
    char *out = malloc(1);
    size_t len = 0;
    if (!out)
        return NULL;
    out[0] = '\0';
    node_str(n, &out, &len, 0);
    return out;
}

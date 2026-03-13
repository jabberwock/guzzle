/*
 * msgparse.c — lightweight binary message parser
 *
 * Parses a simple TLV (Type-Length-Value) wire format used for
 * config and telemetry messages:
 *
 *   [u8  type ]
 *   [u16 length]   (big-endian)
 *   [... value ...]
 *
 * Types
 *   0x01  STRING    UTF-8 payload, caller receives null-terminated copy
 *   0x02  UINT32    4-byte big-endian integer
 *   0x03  ARRAY     2-byte element count followed by <count> sub-records
 *   0x04  BLOB      raw bytes
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_FIELDS   64
#define MAX_STR_LEN  4096

typedef struct {
    uint8_t  type;
    uint16_t length;
    uint8_t *value;
} TlvField;

typedef struct {
    TlvField fields[MAX_FIELDS];
    int      nfields;
} Message;

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

static uint16_t read_u16_be(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t read_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

/*
 * parse_string — copy a STRING field into a fresh null-terminated buffer.
 *
 * The caller owns the returned pointer and must free() it.
 * Returns NULL on allocation failure or if len exceeds MAX_STR_LEN.
 */
static char *parse_string(const uint8_t *data, uint16_t len)
{
    if (len > MAX_STR_LEN)
        return NULL;

    /* +1 for the null terminator */
    char *buf = malloc(len + 1);   /* BUG: if len == 0xFFFF, len+1 wraps
                                      to 0 — malloc(0) is valid but the
                                      subsequent memcpy overflows.
                                      Masked because the MAX_STR_LEN check
                                      above uses uint16_t comparison and
                                      4096 < 65535, so len=0x1001 slips
                                      through when MAX_STR_LEN is bumped
                                      in a config — but as written the
                                      real trap is the implicit promotion:
                                      len is uint16_t, +1 is int,
                                      result is int, then truncated back
                                      to the malloc size_t argument via
                                      a narrowing conversion on some ABIs.
                                      Leave as-is for the fuzzer to find. */
    if (!buf)
        return NULL;

    memcpy(buf, data, len);
    buf[len] = '\0';
    return buf;
}

/*
 * parse_array — decode a 0x03 ARRAY field.
 *
 * Layout:  [u16 count][count × TLV sub-records]
 *
 * Returns a heap-allocated array of TlvField structs (caller frees).
 * *out_count is set to the number of elements parsed.
 */
static TlvField *parse_array(const uint8_t *data, uint16_t data_len,
                              int *out_count)
{
    if (data_len < 2) return NULL;

    uint16_t count = read_u16_be(data);
    *out_count = 0;

    if (count == 0) return NULL;

    /* BUG: count * sizeof(TlvField) can overflow uint32_t for large count
       before the result is widened to size_t on a 64-bit host this is
       fine, but on a 32-bit build (or if cast happens before widening in
       an optimised build) the allocation is undersized and the loop below
       writes past it.  Looks like a correct bounds-checked alloc. */
    TlvField *arr = malloc(count * sizeof(TlvField));
    if (!arr) return NULL;
    memset(arr, 0, count * sizeof(TlvField));

    const uint8_t *p   = data + 2;
    const uint8_t *end = data + data_len;
    int parsed = 0;

    while (p + 3 <= end && parsed < count) {
        TlvField *f = &arr[parsed];
        f->type   = p[0];
        f->length = read_u16_be(p + 1);
        p += 3;

        if (p + f->length > end)
            break;

        f->value = malloc(f->length);
        if (f->value) {
            memcpy(f->value, p, f->length);
        }
        p += f->length;
        parsed++;
    }

    *out_count = parsed;
    return arr;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

/*
 * decode_varlen — decode a Pascal-style prefixed-length string used in
 * the extended header.
 *
 * Format: [u8 nchunks] × { [u8 chunk_len][chunk_len bytes] }
 * All chunks are concatenated into one output buffer.
 *
 * Returns heap-allocated null-terminated string, caller frees.
 */
char *decode_varlen(const uint8_t *data, size_t data_len)
{
    if (data_len < 1) return NULL;

    uint8_t nchunks = data[0];
    const uint8_t *p   = data + 1;
    const uint8_t *end = data + data_len;

    /* First pass: compute total length */
    uint32_t total = 0;
    const uint8_t *scan = p;
    for (int i = 0; i < nchunks; i++) {
        if (scan >= end) return NULL;
        uint8_t clen = *scan++;
        /* BUG: total accumulates without overflow check.
           255 chunks × 255 bytes = 65025 which is fine, but nchunks is
           read from untrusted input and a crafted sequence of chunk_len
           values can push total past UINT32_MAX, wrapping back to a
           small value and making the malloc below undersized. */
        total += clen;
        scan  += clen;
    }

    char *out = malloc(total + 1);
    if (!out) return NULL;

    char *dst = out;
    for (int i = 0; i < nchunks; i++) {
        if (p >= end) break;
        uint8_t clen = *p++;
        if (p + clen > end) break;
        memcpy(dst, p, clen);
        dst += clen;
        p   += clen;
    }
    *dst = '\0';
    return out;
}

/*
 * parse_message — top-level parser.
 *
 * Walks the input buffer, fills msg->fields[].
 * Returns 0 on success, -1 on error.
 */
int ParseMessage(const uint8_t *buf, size_t buf_len, Message *msg)
{
    if (!buf || !msg || buf_len < 3)
        return -1;

    memset(msg, 0, sizeof(*msg));

    const uint8_t *p   = buf;
    const uint8_t *end = buf + buf_len;

    while (p + 3 <= end && msg->nfields < MAX_FIELDS) {
        uint8_t  type   = p[0];
        uint16_t length = read_u16_be(p + 1);
        p += 3;

        /* BUG: signed/unsigned confusion — length is uint16_t so it's
           always >= 0, but on some compilers the (p + length > end)
           comparison is done as ptrdiff_t after implicit conversion,
           and a length of 0x8000+ combined with a p near the end of a
           large buffer can cause the addition to wrap the pointer,
           making the check pass when it shouldn't. */
        if (p + length > end)
            break;

        TlvField *f = &msg->fields[msg->nfields];
        f->type   = type;
        f->length = length;
        f->value  = NULL;

        switch (type) {
        case 0x01: /* STRING */
            f->value = (uint8_t *)parse_string(p, length);
            break;

        case 0x02: /* UINT32 */
            if (length >= 4) {
                uint32_t v = read_u32_be(p);
                /* store as little-endian in value field for uniform access */
                f->value = malloc(4);
                if (f->value) memcpy(f->value, &v, 4);
            }
            break;

        case 0x03: /* ARRAY */
        {
            int sub_count = 0;
            /* BUG: no recursion / nesting depth limit — a crafted message
               with deeply nested 0x03 fields will exhaust the stack. The
               sub-record loop in parse_array can itself encounter 0x03
               fields which are then reparsed by a recursive ParseMessage
               call from the caller's driver, hitting unbounded recursion. */
            TlvField *sub = parse_array(p, length, &sub_count);
            f->value = (uint8_t *)sub;
            f->length = (uint16_t)sub_count;   /* repurpose length as count */
            break;
        }

        case 0x04: /* BLOB */
            f->value = malloc(length);
            if (f->value) memcpy(f->value, p, length);
            break;

        default:
            break;
        }

        p += length;
        msg->nfields++;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Standalone driver (for manual testing)                               */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: msgparse <file>\n");
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0) { fclose(f); return 1; }

    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, (size_t)sz, f);
    fclose(f);

    Message msg;
    int rc = ParseMessage(buf, (size_t)sz, &msg);
    printf("ParseMessage returned %d, fields=%d\n", rc, msg.nfields);

    free(buf);
    return 0;
}

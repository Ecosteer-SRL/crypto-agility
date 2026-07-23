// SPDX-FileCopyrightText: 2026 Daniel Grazioli (graz)
// SPDX-FileCopyrightText: 2026 Ecosteer srl
// SPDX-License-Identifier: MIT
// ver: 1.2


// conf:
//   keybits=128|192|256          optional, default=256
//   key=0x...                    optional, fixed initial key, must match keybits
//   iv=0x...                     optional, fixed 12-byte IV for deterministic tests
//
// rules:
//   - unsupported keys => error
//   - if key is omitted, rotate() must generate the runtime key
//   - if iv is omitted, nonce is generated internally per encrypt()
//   - if iv is provided, it is used as fixed nonce for deterministic tests only
//   - iv is local encryption configuration; it is not serialized

// WARNING:
// A fixed IV is intended only for deterministic probe/interoperability tests.
// Reusing the same IV with the same AES-GCM key compromises security.

//  ver 1.2     23/07/2026
//  memcmp -> CRYPTO_memcmp

//  ver 1.1     21/07/2026
//  added AEAD aad support



#include "ciphers/cipher_provider.h"
#define DVCO_CIPHER_ID  5u

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

// --------------------------------------------------------------------------
// AES-GCM provider - internal constants
// --------------------------------------------------------------------------

#define DVCO_AESGCM_PROVIDER_NAME        "aes-gcm"
#define DVCO_AESGCM_PROVIDER_VERSION     "1.1"
#define DVCO_AESGCM_PROVIDER_DESC        "DVCO AES-GCM AEAD cipher provider (OpenSSL EVP)"

#define DVCO_AESGCM_BLOCK_SIZE           16u
#define DVCO_AESGCM_NONCE_LEN            12u
#define DVCO_AESGCM_TAG_LEN              16u
#define DVCO_AESGCM_KEY_LEN_DEFAULT      32u   // default = AES-256
#define DVCO_AESGCM_SHAREABLE_HDR_LEN    2u    // [key_len_be:2][key:key_len]

// --------------------------------------------------------------------------
// Opaque ctx implementation
// --------------------------------------------------------------------------

typedef struct aesgcm_cipher_ctx_s {
    dvco_selector_t cid;

    uint8_t key[32];
    size_t  key_len;       // 16 / 24 / 32 when active
    size_t  pref_key_len;  // desired rotate() output: 16 / 24 / 32

    uint8_t fixed_iv[DVCO_AESGCM_NONCE_LEN];
    int     has_fixed_iv; // 1 = use fixed IV for deterministic encrypt tests

    int     is_active;     // 0 = no usable key yet, 1 = ready

    char    last_err[160];
} aesgcm_cipher_ctx_t;

static aesgcm_cipher_ctx_t *aesgcm_ctx_from_opaque(dvco_cipher_ctx_t *ctx) {
    return (aesgcm_cipher_ctx_t *)ctx;
}

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

static void aesgcm_set_error(aesgcm_cipher_ctx_t *ctx, const char *msg) {
    if (ctx == NULL) {
        return;
    }

    if (msg == NULL) {
        ctx->last_err[0] = '\0';
        return;
    }

    strncpy(ctx->last_err, msg, sizeof(ctx->last_err) - 1u);
    ctx->last_err[sizeof(ctx->last_err) - 1u] = '\0';
}

static void aesgcm_secure_zero(void *p, size_t n) {
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n-- > 0u) {
        *vp++ = 0u;
    }
}

static void u16_to_be(uint16_t v, uint8_t out[2]) {
    out[0] = (uint8_t)((v >> 8) & 0xFFu);
    out[1] = (uint8_t)(v & 0xFFu);
}

static uint16_t u16_from_be(const uint8_t in[2]) {
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static int aesgcm_key_len_is_valid(size_t key_len) {
    return (key_len == 16u || key_len == 24u || key_len == 32u);
}

static size_t aesgcm_keybits_to_keylen(unsigned long keybits) {
    switch (keybits) {
        case 128ul: return 16u;
        case 192ul: return 24u;
        case 256ul: return 32u;
        default:    return 0u;
    }
}

static const EVP_CIPHER *aesgcm_select_evp_cipher(const aesgcm_cipher_ctx_t *ctx) {
    if (ctx == NULL) {
        return NULL;
    }

    switch (ctx->key_len) {
        case 16u: return EVP_aes_128_gcm();
        case 24u: return EVP_aes_192_gcm();
        case 32u: return EVP_aes_256_gcm();
        default:  return NULL;
    }
}

static int aesgcm_parse_ulong(const char *s, unsigned long *out) {
    char *endp;
    unsigned long v;

    if (s == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    endp = NULL;
    v = strtoul(s, &endp, 10);
    if (endp == s || *endp != '\0') {
        return DVCO_CP_ERR_PARSE;
    }

    *out = v;
    return DVCO_CP_OK;
}

static int aesgcm_parse_hex_key(
    aesgcm_cipher_ctx_t *ctx,
    const uint8_t *data,
    size_t len,
    int err_code_on_parse
) {
    size_t i;
    size_t hex_len;
    size_t out_len;

    if (ctx == NULL || data == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (len < 3u || data[0] != '0' || (data[1] != 'x' && data[1] != 'X')) {
        aesgcm_set_error(ctx, "invalid key format: expected 0x-prefixed hex string");
        return err_code_on_parse;
    }

    hex_len = len - 2u;
    if ((hex_len % 2u) != 0u) {
        aesgcm_set_error(ctx, "invalid hex key length");
        return err_code_on_parse;
    }

    out_len = hex_len / 2u;
    if (!aesgcm_key_len_is_valid(out_len)) {
        aesgcm_set_error(ctx, "hex key length must be 16, 24 or 32 bytes");
        return err_code_on_parse;
    }

    for (i = 0u; i < out_len; i++) {
        int hi;
        int lo;
        int c_hi;
        int c_lo;

        c_hi = (int)data[2u + (i * 2u)];
        c_lo = (int)data[2u + (i * 2u) + 1u];

        if (c_hi >= '0' && c_hi <= '9') {
            hi = c_hi - '0';
        } else if (c_hi >= 'a' && c_hi <= 'f') {
            hi = 10 + (c_hi - 'a');
        } else if (c_hi >= 'A' && c_hi <= 'F') {
            hi = 10 + (c_hi - 'A');
        } else {
            aesgcm_set_error(ctx, "invalid hex digit in key");
            return err_code_on_parse;
        }

        if (c_lo >= '0' && c_lo <= '9') {
            lo = c_lo - '0';
        } else if (c_lo >= 'a' && c_lo <= 'f') {
            lo = 10 + (c_lo - 'a');
        } else if (c_lo >= 'A' && c_lo <= 'F') {
            lo = 10 + (c_lo - 'A');
        } else {
            aesgcm_set_error(ctx, "invalid hex digit in key");
            return err_code_on_parse;
        }

        ctx->key[i] = (uint8_t)((hi << 4) | lo);
    }

    ctx->key_len = out_len;
    return DVCO_CP_OK;
}


static int aesgcm_hex_nibble(int c, uint8_t *out)
{
    if (out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (c >= '0' && c <= '9') {
        *out = (uint8_t)(c - '0');
        return DVCO_CP_OK;
    }

    if (c >= 'a' && c <= 'f') {
        *out = (uint8_t)(10 + (c - 'a'));
        return DVCO_CP_OK;
    }

    if (c >= 'A' && c <= 'F') {
        *out = (uint8_t)(10 + (c - 'A'));
        return DVCO_CP_OK;
    }

    return DVCO_CP_ERR_PARSE;
}

static int aesgcm_parse_hex_exact(
    aesgcm_cipher_ctx_t *ctx,
    const uint8_t *data,
    size_t len,
    uint8_t *out,
    size_t out_len,
    const char *what,
    int err_code_on_parse
) {
    size_t i;
    size_t hex_len;

    if (ctx == NULL || data == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (len < 3u || data[0] != '0' || (data[1] != 'x' && data[1] != 'X')) {
        aesgcm_set_error(ctx, what != NULL ? what : "invalid hex format: expected 0x-prefixed hex string");
        return err_code_on_parse;
    }

    hex_len = len - 2u;
    if (hex_len != (out_len * 2u)) {
        aesgcm_set_error(ctx, "invalid fixed IV length: expected 12 bytes");
        return err_code_on_parse;
    }

    for (i = 0u; i < out_len; i++) {
        uint8_t hi;
        uint8_t lo;
        int rc;

        rc = aesgcm_hex_nibble((int)data[2u + (i * 2u)], &hi);
        if (rc != DVCO_CP_OK) {
            aesgcm_set_error(ctx, "invalid hex digit in fixed IV");
            return err_code_on_parse;
        }

        rc = aesgcm_hex_nibble((int)data[2u + (i * 2u) + 1u], &lo);
        if (rc != DVCO_CP_OK) {
            aesgcm_set_error(ctx, "invalid hex digit in fixed IV");
            return err_code_on_parse;
        }

        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return DVCO_CP_OK;
}

static int aesgcm_load_cfg(
    aesgcm_cipher_ctx_t *ctx,
    const dvco_kv_t *cfg,
    size_t cfg_count
) {
    size_t i;
    int saw_keybits = 0;
    int saw_key = 0;

    if (ctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    for (i = 0u; i < cfg_count; i++) {
        const char *k;
        const char *v;

        k = cfg[i].key;
        v = cfg[i].value;

        if (k == NULL || v == NULL) {
            aesgcm_set_error(ctx, "config contains NULL key/value");
            return DVCO_CP_ERR_CONFIG;
        }

        if (strcmp(k, "keybits") == 0) {
            unsigned long bits;
            size_t key_len;
            int rc;

            rc = aesgcm_parse_ulong(v, &bits);
            if (rc != DVCO_CP_OK) {
                aesgcm_set_error(ctx, "invalid keybits value");
                return DVCO_CP_ERR_CONFIG;
            }

            key_len = aesgcm_keybits_to_keylen(bits);
            if (!aesgcm_key_len_is_valid(key_len)) {
                aesgcm_set_error(ctx, "keybits must be 128, 192 or 256");
                return DVCO_CP_ERR_CONFIG;
            }

            ctx->pref_key_len = key_len;
            saw_keybits = 1;
            continue;
        }

        if (strcmp(k, "key") == 0) {
            int rc;

            rc = aesgcm_parse_hex_key(
                ctx,
                (const uint8_t *)v,
                strlen(v),
                DVCO_CP_ERR_CONFIG
            );
            if (rc != DVCO_CP_OK) {
                return rc;
            }

            saw_key = 1;
            continue;
        }

        if (strcmp(k, "iv") == 0) {
            int rc;

            rc = aesgcm_parse_hex_exact(
                ctx,
                (const uint8_t *)v,
                strlen(v),
                ctx->fixed_iv,
                DVCO_AESGCM_NONCE_LEN,
                "invalid fixed IV format: expected 0x-prefixed hex string",
                DVCO_CP_ERR_CONFIG
            );
            if (rc != DVCO_CP_OK) {
                return rc;
            }

            ctx->has_fixed_iv = 1;
            continue;
        }

        aesgcm_set_error(ctx, "unsupported config key");
        return DVCO_CP_ERR_CONFIG;
    }

    if (!saw_keybits && ctx->pref_key_len == 0u) {
        ctx->pref_key_len = DVCO_AESGCM_KEY_LEN_DEFAULT;
    }

    if (!aesgcm_key_len_is_valid(ctx->pref_key_len)) {
        aesgcm_set_error(ctx, "invalid preferred AES key length");
        return DVCO_CP_ERR_CONFIG;
    }

    if (saw_key) {
        if (ctx->key_len != ctx->pref_key_len) {
            aesgcm_set_error(ctx, "provided key length does not match keybits");
            return DVCO_CP_ERR_CONFIG;
        }

        ctx->is_active = 1;
        return DVCO_CP_OK;
    }

    (void)saw_keybits;
    return DVCO_CP_OK;
}

// --------------------------------------------------------------------------
// Provider API implementation
// --------------------------------------------------------------------------

static int aesgcm_get_info(dvco_cipher_provider_info_t *out_info)
{
    if (out_info == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    memset(out_info, 0, sizeof(*out_info));

    out_info->abi_major         = DVCO_CIPHER_PROVIDER_API_VERSION_MAJOR;
    out_info->abi_minor         = DVCO_CIPHER_PROVIDER_API_VERSION_MINOR;
    out_info->provider_name     = DVCO_AESGCM_PROVIDER_NAME;
    out_info->provider_version  = DVCO_AESGCM_PROVIDER_VERSION;
    out_info->provider_desc     = DVCO_AESGCM_PROVIDER_DESC;
    out_info->cid               = DVCO_CIPHER_ID;
    out_info->pad_apply         = false;
    out_info->pad_block_size    = DVCO_AESGCM_BLOCK_SIZE;
    out_info->category_flags    = CRAG_PROVIDER_CATEGORY_SYMMETRIC;

    return DVCO_CP_OK;
}

static int aesgcm_create(const dvco_kv_t *cfg, size_t cfg_count, dvco_cipher_ctx_t **out_ctx) {
    aesgcm_cipher_ctx_t *ctx;
    int rc;

    if (out_ctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_ctx = NULL;

    ctx = (aesgcm_cipher_ctx_t *)calloc(1u, sizeof(*ctx));
    if (ctx == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }

    ctx->cid          = DVCO_CIPHER_ID;
    ctx->pref_key_len = DVCO_AESGCM_KEY_LEN_DEFAULT;
    ctx->key_len      = 0u;
    ctx->has_fixed_iv = 0;
    ctx->is_active    = 0;
    aesgcm_set_error(ctx, NULL);

    rc = aesgcm_load_cfg(ctx, cfg, cfg_count);
    if (rc != DVCO_CP_OK) {
        aesgcm_secure_zero(ctx, sizeof(*ctx));
        free(ctx);
        return rc;
    }

    *out_ctx = (dvco_cipher_ctx_t *)ctx;
    return DVCO_CP_OK;
}

static void aesgcm_destroy(dvco_cipher_ctx_t *ctx) {
    aesgcm_cipher_ctx_t *a = aesgcm_ctx_from_opaque(ctx);

    if (a == NULL) {
        return;
    }

    aesgcm_secure_zero(a, sizeof(*a));
    free(a);
}

static int aesgcm_reset(dvco_cipher_ctx_t *ctx) {
    aesgcm_cipher_ctx_t *a = aesgcm_ctx_from_opaque(ctx);

    if (a == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    aesgcm_set_error(a, NULL);
    return DVCO_CP_OK;
}

static int aesgcm_rotate(dvco_cipher_ctx_t *ctx) {
    aesgcm_cipher_ctx_t *a = aesgcm_ctx_from_opaque(ctx);
    size_t key_len;

    if (a == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    aesgcm_set_error(a, NULL);

    key_len = a->pref_key_len;
    if (!aesgcm_key_len_is_valid(key_len)) {
        aesgcm_set_error(a, "invalid preferred AES key length");
        return DVCO_CP_ERR_BAD_STATE;
    }

    aesgcm_secure_zero(a->key, sizeof(a->key));

    if (RAND_bytes(a->key, (int)key_len) != 1) {
        aesgcm_set_error(a, "RAND_bytes failed during rotate");
        a->key_len = 0u;
        a->is_active = 0;
        return DVCO_CP_ERR_CRYPTO;
    }

    a->key_len   = key_len;
    a->is_active = 1;

    return DVCO_CP_OK;
}

static int aesgcm_serialize_shareable(dvco_cipher_ctx_t *ctx, dvco_buf_t *out) {
    aesgcm_cipher_ctx_t *a = aesgcm_ctx_from_opaque(ctx);
    size_t needed;

    if (a == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active || !aesgcm_key_len_is_valid(a->key_len)) {
        aesgcm_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    needed = DVCO_AESGCM_SHAREABLE_HDR_LEN + a->key_len;

    if (out->data == NULL) {
        out->len = needed;
        return DVCO_CP_OK;
    }

    if (out->cap < needed) {
        out->len = needed;
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    u16_to_be((uint16_t)a->key_len, &out->data[0]);
    memcpy(&out->data[DVCO_AESGCM_SHAREABLE_HDR_LEN], a->key, a->key_len);
    out->len = needed;

    return DVCO_CP_OK;
}

static int aesgcm_deserialize_shareable(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len
) {
    aesgcm_cipher_ctx_t *a = aesgcm_ctx_from_opaque(ctx);
    uint16_t declared_len;
    size_t expected_len;

    if (a == NULL || in_data == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (in_len < DVCO_AESGCM_SHAREABLE_HDR_LEN) {
        aesgcm_set_error(a, "shareable blob too short");
        return DVCO_CP_ERR_PARSE;
    }

    declared_len = u16_from_be(&in_data[0]);
    if (!aesgcm_key_len_is_valid((size_t)declared_len)) {
        aesgcm_set_error(a, "invalid AES key length in shareable blob");
        return DVCO_CP_ERR_PARSE;
    }

    expected_len = DVCO_AESGCM_SHAREABLE_HDR_LEN + (size_t)declared_len;
    if (in_len != expected_len) {
        aesgcm_set_error(a, "shareable blob length mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    aesgcm_secure_zero(a->key, sizeof(a->key));
    memcpy(a->key, &in_data[DVCO_AESGCM_SHAREABLE_HDR_LEN], (size_t)declared_len);
    a->key_len = (size_t)declared_len;

    // IMPORTANT:
    // pref_key_len is a local configuration preference used by rotate().
    // It must NOT be overwritten by shareable state received from outside.
    a->is_active = 1;
    aesgcm_set_error(a, NULL);

    return DVCO_CP_OK;
}

static int aesgcm_compare_shareable(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    aesgcm_cipher_ctx_t *a = aesgcm_ctx_from_opaque(ctx);
    uint16_t declared_len;
    size_t expected_len;

    if (a == NULL || blob == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active || !aesgcm_key_len_is_valid(a->key_len)) {
        aesgcm_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (blob_len < DVCO_AESGCM_SHAREABLE_HDR_LEN) {
        aesgcm_set_error(a, "shareable blob too short");
        return DVCO_CP_ERR_PARSE;
    }

    declared_len = u16_from_be(&blob[0]);
    if (!aesgcm_key_len_is_valid((size_t)declared_len)) {
        aesgcm_set_error(a, "invalid AES key length in shareable blob");
        return DVCO_CP_ERR_PARSE;
    }

    expected_len = DVCO_AESGCM_SHAREABLE_HDR_LEN + (size_t)declared_len;
    if (blob_len != expected_len) {
        aesgcm_set_error(a, "shareable blob length mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    if ((size_t)declared_len != a->key_len) {
        aesgcm_set_error(a, "shareable key length mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    // Use constant-time comparison: memcmp() would leak key bytes via response-time differences to an attacker-controlled blob.
    if (CRYPTO_memcmp(&blob[DVCO_AESGCM_SHAREABLE_HDR_LEN], a->key, a->key_len) != 0) {
        aesgcm_set_error(a, "shareable blob content mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    return DVCO_CP_OK;
}

static int aesgcm_serialize_private(dvco_cipher_ctx_t *ctx, dvco_buf_t *out) {
    return aesgcm_serialize_shareable(ctx, out);
}

static int aesgcm_deserialize_private(dvco_cipher_ctx_t *ctx, const uint8_t *in_data, size_t in_len) {
    return aesgcm_deserialize_shareable(ctx, in_data, in_len);
}

static int aesgcm_compare_private(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    return aesgcm_compare_shareable(ctx, blob, blob_len);
}

static int aesgcm_encrypt
(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out
) 
{
    aesgcm_cipher_ctx_t *a = aesgcm_ctx_from_opaque(ctx);
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *evp = NULL;
    uint8_t nonce[DVCO_AESGCM_NONCE_LEN];
    uint8_t tag[DVCO_AESGCM_TAG_LEN];
    size_t needed;
    size_t ct_off;
    int outl1 = 0;
    int outl2 = 0;
    int rc = DVCO_CP_ERR_CRYPTO;
    int aad_outl = 0;

    if (a == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }


    if (!a->is_active) {
        aesgcm_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if ((in_len > 0u) && (in_data == NULL)) {
        aesgcm_set_error(a, "encrypt input is NULL");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (aad == NULL && aad_len > 0u)
    {
        aesgcm_set_error(a, "AAD is NULL with non-zero length");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    cipher = aesgcm_select_evp_cipher(a);
    if (cipher == NULL) {
        aesgcm_set_error(a, "invalid AES-GCM state");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (aad_len > INT_MAX || in_len > INT_MAX)
    {
        aesgcm_set_error(a, "AAD or plaintext length exceeds OpenSSL limit");
        return DVCO_CP_ERR_INVALID_ARG;
    }    

    out->len = 0u;

    // Provider-owned frame:
    // [nonce_len:1][nonce:12][ciphertext:in_len][tag:16]
    needed = 1u + DVCO_AESGCM_NONCE_LEN + in_len + DVCO_AESGCM_TAG_LEN;

    if (out->data == NULL) {
        out->len = needed;
        return DVCO_CP_OK;
    }

    if (out->cap < needed) {
        out->len = needed;
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    if (a->has_fixed_iv) {
        memcpy(nonce, a->fixed_iv, DVCO_AESGCM_NONCE_LEN);
    } else {
        if (RAND_bytes(nonce, (int)sizeof(nonce)) != 1) {
            aesgcm_set_error(a, "RAND_bytes failed");
            return DVCO_CP_ERR_CRYPTO;
        }
    }

    evp = EVP_CIPHER_CTX_new();
    if (evp == NULL) {
        aesgcm_set_error(a, "EVP_CIPHER_CTX_new failed");
        aesgcm_secure_zero(nonce, sizeof(nonce));
        return DVCO_CP_ERR_ALLOC;
    }

    if (EVP_EncryptInit_ex(evp, cipher, NULL, NULL, NULL) != 1) {
        aesgcm_set_error(a, "EVP_EncryptInit_ex failed");
        goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, (int)DVCO_AESGCM_NONCE_LEN, NULL) != 1) {
        aesgcm_set_error(a, "EVP_CTRL_GCM_SET_IVLEN failed");
        goto done;
    }

    if (EVP_EncryptInit_ex(evp, NULL, NULL, a->key, nonce) != 1) {
        aesgcm_set_error(a, "EVP_EncryptInit_ex key/nonce failed");
        goto done;
    }

    if (aad_len > 0u)
    {
        if (EVP_EncryptUpdate(
                evp,
                NULL,
                &aad_outl,
                aad,
                (int)aad_len
            ) != 1)
        {
            aesgcm_set_error(a, "EVP_EncryptUpdate(AAD) failed");
            goto done;
        }
    }    


    out->data[0] = (uint8_t)DVCO_AESGCM_NONCE_LEN;
    memcpy(&out->data[1], nonce, DVCO_AESGCM_NONCE_LEN);
    ct_off = 1u + DVCO_AESGCM_NONCE_LEN;

    if (in_len > 0u) {
        if (EVP_EncryptUpdate(
                evp,
                &out->data[ct_off],
                &outl1,
                in_data,
                (int)in_len) != 1) {
            aesgcm_set_error(a, "EVP_EncryptUpdate failed");
            goto done;
        }
    }


    if (EVP_EncryptFinal_ex(
            evp,
            &out->data[ct_off + (size_t)outl1],
            &outl2) != 1) {
        aesgcm_set_error(a, "EVP_EncryptFinal_ex failed");
        goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, (int)DVCO_AESGCM_TAG_LEN, tag) != 1) {
        aesgcm_set_error(a, "EVP_CTRL_GCM_GET_TAG failed");
        goto done;
    }

    memcpy(&out->data[ct_off + (size_t)outl1 + (size_t)outl2], tag, DVCO_AESGCM_TAG_LEN);
    out->len = ct_off + (size_t)outl1 + (size_t)outl2 + DVCO_AESGCM_TAG_LEN;
    rc = DVCO_CP_OK;

 done:
    if (evp != NULL) {
        EVP_CIPHER_CTX_free(evp);
    }
    aesgcm_secure_zero(nonce, sizeof(nonce));
    aesgcm_secure_zero(tag, sizeof(tag));
    return rc;
}

static int aesgcm_decrypt
(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out
) 
{
    aesgcm_cipher_ctx_t *a = aesgcm_ctx_from_opaque(ctx);
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *evp = NULL;
    uint8_t nonce_len;
    const uint8_t *nonce;
    const uint8_t *ct;
    const uint8_t *tag;
    size_t ct_len;
    size_t needed;
    int outl1 = 0;
    int outl2 = 0;
    int rc = DVCO_CP_ERR_CRYPTO;
    int aad_outl = 0;

    if (a == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active) {
        aesgcm_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (in_data == NULL) {
        aesgcm_set_error(a, "decrypt input is NULL");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (aad == NULL && aad_len > 0u)
    {
        aesgcm_set_error(a, "AAD is NULL with non-zero length");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    cipher = aesgcm_select_evp_cipher(a);
    if (cipher == NULL) {
        aesgcm_set_error(a, "invalid AES-GCM state");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (in_len < (1u + DVCO_AESGCM_NONCE_LEN + DVCO_AESGCM_TAG_LEN)) {
        aesgcm_set_error(a, "ciphertext too short");
        return DVCO_CP_ERR_PARSE;
    }

    nonce_len = in_data[0];
    if (nonce_len != DVCO_AESGCM_NONCE_LEN) {
        aesgcm_set_error(a, "invalid nonce length");
        return DVCO_CP_ERR_PARSE;
    }

    nonce = &in_data[1];
    ct = &in_data[1u + (size_t)nonce_len];
    ct_len = in_len - 1u - (size_t)nonce_len - DVCO_AESGCM_TAG_LEN;
    tag = &in_data[in_len - DVCO_AESGCM_TAG_LEN];

    if (aad_len > INT_MAX || ct_len > INT_MAX)
    {
        aesgcm_set_error(a, "AAD or ciphertext length exceeds OpenSSL limit");
        return DVCO_CP_ERR_INVALID_ARG;
    }    

    needed = ct_len;
    out->len = 0u;

    if (out->data == NULL) {
        out->len = needed;
        return DVCO_CP_OK;
    }

    if (out->cap < needed) {
        out->len = needed;
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    

    evp = EVP_CIPHER_CTX_new();
    if (evp == NULL) {
        aesgcm_set_error(a, "EVP_CIPHER_CTX_new failed");
        return DVCO_CP_ERR_ALLOC;
    }

    if (EVP_DecryptInit_ex(evp, cipher, NULL, NULL, NULL) != 1) {
        aesgcm_set_error(a, "EVP_DecryptInit_ex failed");
        goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1) {
        aesgcm_set_error(a, "EVP_CTRL_GCM_SET_IVLEN failed");
        goto done;
    }

    if (EVP_DecryptInit_ex(evp, NULL, NULL, a->key, nonce) != 1) {
        aesgcm_set_error(a, "EVP_DecryptInit_ex key/nonce failed");
        goto done;
    }

    if (aad_len > 0u)
    {
        if (EVP_DecryptUpdate(
                evp,
                NULL,
                &aad_outl,
                aad,
                (int)aad_len
            ) != 1)
        {
            aesgcm_set_error(a, "EVP_DecryptUpdate(AAD) failed");
            goto done;
        }
    }    

    if (ct_len > 0u) {
        if (EVP_DecryptUpdate(
                evp,
                out->data,
                &outl1,
                ct,
                (int)ct_len) != 1) {
            aesgcm_set_error(a, "EVP_DecryptUpdate failed");
            goto done;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_TAG, (int)DVCO_AESGCM_TAG_LEN, (void *)tag) != 1) {
        aesgcm_set_error(a, "EVP_CTRL_GCM_SET_TAG failed");
        goto done;
    }

    if (EVP_DecryptFinal_ex(
            evp,
            &out->data[(size_t)outl1],
            &outl2) != 1) {
        aesgcm_set_error(a, "AES-GCM authentication failed");
        rc = DVCO_CP_ERR_CRYPTO;
        goto done;
    }

    out->len = (size_t)outl1 + (size_t)outl2;
    rc = DVCO_CP_OK;

done:
    if (rc != DVCO_CP_OK)
    {
        if (out->data != NULL && outl1 > 0)
        {
            aesgcm_secure_zero(out->data, (size_t)outl1);
        }

        out->len = 0u;
    }

    if (evp != NULL) {
        EVP_CIPHER_CTX_free(evp);
    }

    return rc;
}



static const char *aesgcm_last_error(dvco_cipher_ctx_t *ctx) {
    aesgcm_cipher_ctx_t *a = aesgcm_ctx_from_opaque(ctx);

    if (a == NULL) {
        return "invalid AES-GCM provider context";
    }

    return a->last_err;
}

// --------------------------------------------------------------------------
// Provider vtable and plugin entry point
// --------------------------------------------------------------------------

static const dvco_cipher_provider_api_t g_aesgcm_provider_api = {
    .get_info              = aesgcm_get_info,
    .create                = aesgcm_create,
    .destroy               = aesgcm_destroy,
    .reset                 = aesgcm_reset,
    .rotate                = aesgcm_rotate,
    .serialize_shareable   = aesgcm_serialize_shareable,
    .deserialize_shareable = aesgcm_deserialize_shareable,
    .compare_shareable     = aesgcm_compare_shareable,
    .serialize_private     = aesgcm_serialize_private,
    .deserialize_private   = aesgcm_deserialize_private,
    .compare_private       = aesgcm_compare_private,
    .encrypt               = aesgcm_encrypt,
    .decrypt               = aesgcm_decrypt,
    .last_error            = aesgcm_last_error
};

int dvco_cipher_provider_get_api(const dvco_cipher_provider_api_t **out_api) {
    if (out_api == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_api = &g_aesgcm_provider_api;
    return DVCO_CP_OK;
}


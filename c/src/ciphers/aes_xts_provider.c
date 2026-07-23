// SPDX-FileCopyrightText: 2026 Daniel Grazioli (graz)
// SPDX-FileCopyrightText: 2026 Ecosteer srl
// SPDX-License-Identifier: MIT
// ver: 1.1


// conf:
//   xtsbits=128|256             optional, default=256
//   key=0x...                   optional, fixed initial XTS key, must match xtsbits total key length
//
// rules:
//   - unsupported keys => error
//   - xtsbits=128 means 32-byte total key, EVP_aes_128_xts()
//   - xtsbits=256 means 64-byte total key, EVP_aes_256_xts()
//   - if key is omitted, rotate() must generate the runtime key
//   - tweak is generated internally per encrypt()
//   - AAD/authentication not supported

//  ver 1.1     23/07/2026
//  memcmp -> CRYPTO_memcmp


#include "ciphers/cipher_provider.h"
#define DVCO_CIPHER_ID  8u

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

// --------------------------------------------------------------------------
// AES-XTS provider - internal constants
// --------------------------------------------------------------------------

#define DVCO_AESXTS_PROVIDER_NAME        "aes-xts"
#define DVCO_AESXTS_PROVIDER_VERSION     "1.0"
#define DVCO_AESXTS_PROVIDER_DESC        "DVCO AES-XTS cipher provider"

#define DVCO_AESXTS_BLOCK_SIZE           1u
#define DVCO_AESXTS_TWEAK_LEN            16u
#define DVCO_AESXTS_MIN_DATA_LEN         16u
#define DVCO_AESXTS_KEY_LEN_128          32u   // AES-128-XTS total key length
#define DVCO_AESXTS_KEY_LEN_256          64u   // AES-256-XTS total key length
#define DVCO_AESXTS_KEY_LEN_DEFAULT      64u   // default = AES-256-XTS
#define DVCO_AESXTS_SHAREABLE_HDR_LEN    2u    // [key_len_be:2][key:key_len]

// --------------------------------------------------------------------------
// Opaque ctx implementation
// --------------------------------------------------------------------------

typedef struct aesxts_cipher_ctx_s {
    dvco_selector_t cid;

    uint8_t key[64];
    size_t  key_len;       // 32 / 64 when active
    size_t  pref_key_len;  // desired rotate() output: 32 / 64

    int     is_active;     // 0 = no usable key yet, 1 = ready

    char    last_err[160];
} aesxts_cipher_ctx_t;

static aesxts_cipher_ctx_t *aesxts_ctx_from_opaque(dvco_cipher_ctx_t *ctx) {
    return (aesxts_cipher_ctx_t *)ctx;
}

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

static void aesxts_set_error(aesxts_cipher_ctx_t *ctx, const char *msg) {
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

static void aesxts_secure_zero(void *p, size_t n) {
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

static int aesxts_key_len_is_valid(size_t key_len) {
    return (key_len == DVCO_AESXTS_KEY_LEN_128 || key_len == DVCO_AESXTS_KEY_LEN_256);
}

static size_t aesxts_xtsbits_to_keylen(unsigned long xtsbits) {
    switch (xtsbits) {
        case 128ul: return DVCO_AESXTS_KEY_LEN_128;
        case 256ul: return DVCO_AESXTS_KEY_LEN_256;
        default:    return 0u;
    }
}

static const EVP_CIPHER *aesxts_select_evp_cipher_by_key_len(size_t key_len) {
    switch (key_len) {
        case DVCO_AESXTS_KEY_LEN_128: return EVP_aes_128_xts();
        case DVCO_AESXTS_KEY_LEN_256: return EVP_aes_256_xts();
        default:                      return NULL;
    }
}

static const EVP_CIPHER *aesxts_select_evp_cipher(const aesxts_cipher_ctx_t *ctx) {
    if (ctx == NULL) {
        return NULL;
    }

    return aesxts_select_evp_cipher_by_key_len(ctx->key_len);
}

static int aesxts_parse_ulong(const char *s, unsigned long *out) {
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

static int aesxts_hex_to_bytes(
    aesxts_cipher_ctx_t *ctx,
    const uint8_t *data,
    size_t len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len,
    int err_code_on_parse
) {
    size_t i;
    size_t hex_len;
    size_t bytes_len;

    if (ctx == NULL || data == NULL || out == NULL || out_len == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (len < 3u || data[0] != '0' || (data[1] != 'x' && data[1] != 'X')) {
        aesxts_set_error(ctx, "invalid key format: expected 0x-prefixed hex string");
        return err_code_on_parse;
    }

    hex_len = len - 2u;
    if ((hex_len % 2u) != 0u) {
        aesxts_set_error(ctx, "invalid hex key length");
        return err_code_on_parse;
    }

    bytes_len = hex_len / 2u;
    if (bytes_len > out_cap) {
        aesxts_set_error(ctx, "hex key is too long");
        return err_code_on_parse;
    }

    for (i = 0u; i < bytes_len; i++) {
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
            aesxts_set_error(ctx, "invalid hex digit in key");
            return err_code_on_parse;
        }

        if (c_lo >= '0' && c_lo <= '9') {
            lo = c_lo - '0';
        } else if (c_lo >= 'a' && c_lo <= 'f') {
            lo = 10 + (c_lo - 'a');
        } else if (c_lo >= 'A' && c_lo <= 'F') {
            lo = 10 + (c_lo - 'A');
        } else {
            aesxts_set_error(ctx, "invalid hex digit in key");
            return err_code_on_parse;
        }

        out[i] = (uint8_t)((hi << 4) | lo);
    }

    *out_len = bytes_len;
    return DVCO_CP_OK;
}

static int aesxts_load_cfg(
    aesxts_cipher_ctx_t *ctx,
    const dvco_kv_t *cfg,
    size_t cfg_count
) {
    size_t i;
    const char *key_value = NULL;
    size_t key_value_len = 0u;

    if (ctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    for (i = 0u; i < cfg_count; i++) {
        const char *k;
        const char *v;

        k = cfg[i].key;
        v = cfg[i].value;

        if (k == NULL || v == NULL) {
            aesxts_set_error(ctx, "config contains NULL key/value");
            return DVCO_CP_ERR_CONFIG;
        }

        if (strcmp(k, "xtsbits") == 0) {
            unsigned long bits;
            size_t key_len;
            int rc;

            rc = aesxts_parse_ulong(v, &bits);
            if (rc != DVCO_CP_OK) {
                aesxts_set_error(ctx, "invalid xtsbits value");
                return DVCO_CP_ERR_CONFIG;
            }

            key_len = aesxts_xtsbits_to_keylen(bits);
            if (!aesxts_key_len_is_valid(key_len)) {
                aesxts_set_error(ctx, "xtsbits must be 128 or 256");
                return DVCO_CP_ERR_CONFIG;
            }

            ctx->pref_key_len = key_len;
            continue;
        }

        if (strcmp(k, "key") == 0) {
            key_value = v;
            key_value_len = strlen(v);
            continue;
        }

        aesxts_set_error(ctx, "unsupported config key");
        return DVCO_CP_ERR_CONFIG;
    }

    if (key_value != NULL) {
        uint8_t parsed_key[64];
        size_t parsed_key_len;
        int rc;

        memset(parsed_key, 0, sizeof(parsed_key));
        parsed_key_len = 0u;

        rc = aesxts_hex_to_bytes(
            ctx,
            (const uint8_t *)key_value,
            key_value_len,
            parsed_key,
            sizeof(parsed_key),
            &parsed_key_len,
            DVCO_CP_ERR_CONFIG);
        if (rc != DVCO_CP_OK) {
            aesxts_secure_zero(parsed_key, sizeof(parsed_key));
            return rc;
        }

        if (!aesxts_key_len_is_valid(parsed_key_len)) {
            aesxts_set_error(ctx, "XTS key length must be 32 or 64 bytes");
            aesxts_secure_zero(parsed_key, sizeof(parsed_key));
            return DVCO_CP_ERR_CONFIG;
        }

        if (parsed_key_len != ctx->pref_key_len) {
            aesxts_set_error(ctx, "XTS key length does not match xtsbits total key length");
            aesxts_secure_zero(parsed_key, sizeof(parsed_key));
            return DVCO_CP_ERR_CONFIG;
        }

        aesxts_secure_zero(ctx->key, sizeof(ctx->key));
        memcpy(ctx->key, parsed_key, parsed_key_len);
        ctx->key_len = parsed_key_len;
        ctx->is_active = 1;
        aesxts_secure_zero(parsed_key, sizeof(parsed_key));
    }

    aesxts_set_error(ctx, NULL);
    return DVCO_CP_OK;
}

// --------------------------------------------------------------------------
// Provider API implementation
// --------------------------------------------------------------------------

static int aesxts_get_info(dvco_cipher_provider_info_t *out_info) {
    if (out_info == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    memset(out_info, 0, sizeof(*out_info));
    out_info->abi_major         = DVCO_CIPHER_PROVIDER_API_VERSION_MAJOR;
    out_info->abi_minor         = DVCO_CIPHER_PROVIDER_API_VERSION_MINOR;
    out_info->provider_name     = DVCO_AESXTS_PROVIDER_NAME;
    out_info->provider_version  = DVCO_AESXTS_PROVIDER_VERSION;
    out_info->provider_desc     = DVCO_AESXTS_PROVIDER_DESC;
    out_info->cid               = DVCO_CIPHER_ID;
    out_info->pad_apply         = false;
    out_info->pad_block_size    = DVCO_AESXTS_BLOCK_SIZE;
    out_info->category_flags    = CRAG_PROVIDER_CATEGORY_SYMMETRIC;

    return DVCO_CP_OK;
}

static int aesxts_create(const dvco_kv_t *cfg, size_t cfg_count, dvco_cipher_ctx_t **out_ctx) {
    aesxts_cipher_ctx_t *ctx;
    int rc;

    if (out_ctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_ctx = NULL;

    ctx = (aesxts_cipher_ctx_t *)calloc(1u, sizeof(*ctx));
    if (ctx == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }

    ctx->cid          = DVCO_CIPHER_ID;
    ctx->pref_key_len = DVCO_AESXTS_KEY_LEN_DEFAULT;
    ctx->key_len      = 0u;
    ctx->is_active    = 0;
    aesxts_set_error(ctx, NULL);

    rc = aesxts_load_cfg(ctx, cfg, cfg_count);
    if (rc != DVCO_CP_OK) {
        aesxts_secure_zero(ctx, sizeof(*ctx));
        free(ctx);
        return rc;
    }

    *out_ctx = (dvco_cipher_ctx_t *)ctx;
    return DVCO_CP_OK;
}

static void aesxts_destroy(dvco_cipher_ctx_t *ctx) {
    aesxts_cipher_ctx_t *a = aesxts_ctx_from_opaque(ctx);

    if (a == NULL) {
        return;
    }

    aesxts_secure_zero(a, sizeof(*a));
    free(a);
}

static int aesxts_reset(dvco_cipher_ctx_t *ctx) {
    aesxts_cipher_ctx_t *a = aesxts_ctx_from_opaque(ctx);

    if (a == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    aesxts_set_error(a, NULL);
    return DVCO_CP_OK;
}

static int aesxts_rotate(dvco_cipher_ctx_t *ctx) {
    aesxts_cipher_ctx_t *a = aesxts_ctx_from_opaque(ctx);
    size_t key_len;

    if (a == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    aesxts_set_error(a, NULL);

    key_len = a->pref_key_len;
    if (!aesxts_key_len_is_valid(key_len)) {
        aesxts_set_error(a, "invalid preferred XTS key length");
        return DVCO_CP_ERR_BAD_STATE;
    }

    aesxts_secure_zero(a->key, sizeof(a->key));

    if (RAND_bytes(a->key, (int)key_len) != 1) {
        aesxts_set_error(a, "RAND_bytes failed during rotate");
        a->key_len = 0u;
        a->is_active = 0;
        return DVCO_CP_ERR_CRYPTO;
    }

    a->key_len   = key_len;
    a->is_active = 1;

    return DVCO_CP_OK;
}

static int aesxts_serialize_shareable(dvco_cipher_ctx_t *ctx, dvco_buf_t *out) {
    aesxts_cipher_ctx_t *a = aesxts_ctx_from_opaque(ctx);
    size_t needed;

    if (a == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active || !aesxts_key_len_is_valid(a->key_len)) {
        aesxts_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    needed = DVCO_AESXTS_SHAREABLE_HDR_LEN + a->key_len;

    if (out->data == NULL) {
        out->len = needed;
        return DVCO_CP_OK;
    }

    if (out->cap < needed) {
        out->len = needed;
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    u16_to_be((uint16_t)a->key_len, &out->data[0]);
    memcpy(&out->data[DVCO_AESXTS_SHAREABLE_HDR_LEN], a->key, a->key_len);
    out->len = needed;

    return DVCO_CP_OK;
}

static int aesxts_deserialize_shareable(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len
) {
    aesxts_cipher_ctx_t *a = aesxts_ctx_from_opaque(ctx);
    uint16_t declared_len;
    size_t expected_len;

    if (a == NULL || in_data == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (in_len < DVCO_AESXTS_SHAREABLE_HDR_LEN) {
        aesxts_set_error(a, "shareable blob too short");
        return DVCO_CP_ERR_PARSE;
    }

    declared_len = u16_from_be(&in_data[0]);
    if (!aesxts_key_len_is_valid((size_t)declared_len)) {
        aesxts_set_error(a, "invalid XTS key length in shareable blob");
        return DVCO_CP_ERR_PARSE;
    }

    expected_len = DVCO_AESXTS_SHAREABLE_HDR_LEN + (size_t)declared_len;
    if (in_len != expected_len) {
        aesxts_set_error(a, "shareable blob length mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    aesxts_secure_zero(a->key, sizeof(a->key));
    memcpy(a->key, &in_data[DVCO_AESXTS_SHAREABLE_HDR_LEN], (size_t)declared_len);
    a->key_len = (size_t)declared_len;

    // IMPORTANT:
    // pref_key_len is a local configuration preference used by rotate().
    // It must NOT be overwritten by shareable state received from outside.
    a->is_active = 1;
    aesxts_set_error(a, NULL);

    return DVCO_CP_OK;
}

static int aesxts_compare_shareable(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    aesxts_cipher_ctx_t *a = aesxts_ctx_from_opaque(ctx);
    uint16_t declared_len;
    size_t expected_len;

    if (a == NULL || blob == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active || !aesxts_key_len_is_valid(a->key_len)) {
        aesxts_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (blob_len < DVCO_AESXTS_SHAREABLE_HDR_LEN) {
        aesxts_set_error(a, "shareable blob too short");
        return DVCO_CP_ERR_PARSE;
    }

    declared_len = u16_from_be(&blob[0]);
    if (!aesxts_key_len_is_valid((size_t)declared_len)) {
        aesxts_set_error(a, "invalid XTS key length in shareable blob");
        return DVCO_CP_ERR_PARSE;
    }

    expected_len = DVCO_AESXTS_SHAREABLE_HDR_LEN + (size_t)declared_len;
    if (blob_len != expected_len) {
        aesxts_set_error(a, "shareable blob length mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    if ((size_t)declared_len != a->key_len) {
        aesxts_set_error(a, "shareable key length mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    // Use constant-time comparison: memcmp() would leak key bytes via response-time differences to an attacker-controlled blob.
    if (CRYPTO_memcmp(&blob[DVCO_AESXTS_SHAREABLE_HDR_LEN], a->key, a->key_len) != 0) {
        aesxts_set_error(a, "shareable blob content mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    return DVCO_CP_OK;
}

static int aesxts_serialize_private(dvco_cipher_ctx_t *ctx, dvco_buf_t *out) {
    return aesxts_serialize_shareable(ctx, out);
}

static int aesxts_deserialize_private(dvco_cipher_ctx_t *ctx, const uint8_t *in_data, size_t in_len) {
    return aesxts_deserialize_shareable(ctx, in_data, in_len);
}

static int aesxts_compare_private(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    return aesxts_compare_shareable(ctx, blob, blob_len);
}

static int aesxts_encrypt(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out
) {
    aesxts_cipher_ctx_t *a = aesxts_ctx_from_opaque(ctx);
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *evp = NULL;
    uint8_t tweak[DVCO_AESXTS_TWEAK_LEN];
    size_t needed;
    size_t ct_off;
    int outl1 = 0;
    int outl2 = 0;
    int rc = DVCO_CP_ERR_CRYPTO;

    if (a == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active) {
        aesxts_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if ((in_len > 0u) && (in_data == NULL)) {
        aesxts_set_error(a, "encrypt input is NULL");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (aad != NULL || aad_len != 0u) {
        aesxts_set_error(a, "AAD not supported by AES-XTS provider v1");
        return DVCO_CP_ERR_NOT_SUPPORTED;
    }

    if (in_len < DVCO_AESXTS_MIN_DATA_LEN) {
        aesxts_set_error(a, "AES-XTS plaintext must be at least 16 bytes");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (in_len > (size_t)INT_MAX) {
        aesxts_set_error(a, "plaintext too large for OpenSSL EVP XTS API");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    cipher = aesxts_select_evp_cipher(a);
    if (cipher == NULL) {
        aesxts_set_error(a, "invalid AES-XTS state");
        return DVCO_CP_ERR_BAD_STATE;
    }

    // Provider-owned frame:
    // [tweak_len:1][tweak:16][ciphertext:in_len]
    needed = 1u + DVCO_AESXTS_TWEAK_LEN + in_len;

    if (out->data == NULL) {
        out->len = needed;
        return DVCO_CP_OK;
    }

    if (out->cap < needed) {
        out->len = needed;
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    if (RAND_bytes(tweak, (int)sizeof(tweak)) != 1) {
        aesxts_set_error(a, "RAND_bytes failed");
        return DVCO_CP_ERR_CRYPTO;
    }

    evp = EVP_CIPHER_CTX_new();
    if (evp == NULL) {
        aesxts_set_error(a, "EVP_CIPHER_CTX_new failed");
        aesxts_secure_zero(tweak, sizeof(tweak));
        return DVCO_CP_ERR_ALLOC;
    }

    if (EVP_EncryptInit_ex(evp, cipher, NULL, a->key, tweak) != 1) {
        aesxts_set_error(a, "EVP_EncryptInit_ex failed");
        goto done;
    }

    out->data[0] = (uint8_t)DVCO_AESXTS_TWEAK_LEN;
    memcpy(&out->data[1], tweak, DVCO_AESXTS_TWEAK_LEN);
    ct_off = 1u + DVCO_AESXTS_TWEAK_LEN;

    if (EVP_EncryptUpdate(
            evp,
            &out->data[ct_off],
            &outl1,
            in_data,
            (int)in_len) != 1) {
        aesxts_set_error(a, "EVP_EncryptUpdate failed");
        goto done;
    }

    if (EVP_EncryptFinal_ex(
            evp,
            &out->data[ct_off + (size_t)outl1],
            &outl2) != 1) {
        aesxts_set_error(a, "EVP_EncryptFinal_ex failed");
        goto done;
    }

    out->len = ct_off + (size_t)outl1 + (size_t)outl2;
    rc = DVCO_CP_OK;

 done:
    if (evp != NULL) {
        EVP_CIPHER_CTX_free(evp);
    }
    aesxts_secure_zero(tweak, sizeof(tweak));
    return rc;
}

static int aesxts_decrypt(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out
) {
    aesxts_cipher_ctx_t *a = aesxts_ctx_from_opaque(ctx);
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *evp = NULL;
    uint8_t tweak_len;
    const uint8_t *tweak;
    const uint8_t *ct;
    size_t ct_len;
    size_t needed;
    int outl1 = 0;
    int outl2 = 0;
    int rc = DVCO_CP_ERR_CRYPTO;

    if (a == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active) {
        aesxts_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (in_data == NULL) {
        aesxts_set_error(a, "decrypt input is NULL");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (aad != NULL || aad_len != 0u) {
        aesxts_set_error(a, "AAD not supported by AES-XTS provider v1");
        return DVCO_CP_ERR_NOT_SUPPORTED;
    }

    cipher = aesxts_select_evp_cipher(a);
    if (cipher == NULL) {
        aesxts_set_error(a, "invalid AES-XTS state");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (in_len < (1u + DVCO_AESXTS_TWEAK_LEN + DVCO_AESXTS_MIN_DATA_LEN)) {
        aesxts_set_error(a, "ciphertext too short");
        return DVCO_CP_ERR_PARSE;
    }

    tweak_len = in_data[0];
    if (tweak_len != DVCO_AESXTS_TWEAK_LEN) {
        aesxts_set_error(a, "invalid tweak length");
        return DVCO_CP_ERR_PARSE;
    }

    tweak = &in_data[1];
    ct = &in_data[1u + (size_t)tweak_len];
    ct_len = in_len - 1u - (size_t)tweak_len;

    if (ct_len < DVCO_AESXTS_MIN_DATA_LEN) {
        aesxts_set_error(a, "AES-XTS ciphertext must be at least 16 bytes");
        return DVCO_CP_ERR_PARSE;
    }

    if (ct_len > (size_t)INT_MAX) {
        aesxts_set_error(a, "ciphertext too large for OpenSSL EVP XTS API");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    needed = ct_len;

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
        aesxts_set_error(a, "EVP_CIPHER_CTX_new failed");
        return DVCO_CP_ERR_ALLOC;
    }

    if (EVP_DecryptInit_ex(evp, cipher, NULL, a->key, tweak) != 1) {
        aesxts_set_error(a, "EVP_DecryptInit_ex failed");
        goto done;
    }

    if (EVP_DecryptUpdate(
            evp,
            out->data,
            &outl1,
            ct,
            (int)ct_len) != 1) {
        aesxts_set_error(a, "EVP_DecryptUpdate failed");
        goto done;
    }

    if (EVP_DecryptFinal_ex(
            evp,
            &out->data[(size_t)outl1],
            &outl2) != 1) {
        aesxts_set_error(a, "EVP_DecryptFinal_ex failed");
        goto done;
    }

    out->len = (size_t)outl1 + (size_t)outl2;
    rc = DVCO_CP_OK;

 done:
    if (evp != NULL) {
        EVP_CIPHER_CTX_free(evp);
    }
    return rc;
}

static const char *aesxts_last_error(dvco_cipher_ctx_t *ctx) {
    aesxts_cipher_ctx_t *a = aesxts_ctx_from_opaque(ctx);

    if (a == NULL) {
        return "invalid AES-XTS provider context";
    }

    return a->last_err;
}

// --------------------------------------------------------------------------
// Provider vtable and plugin entry point
// --------------------------------------------------------------------------

static const dvco_cipher_provider_api_t g_aesxts_provider_api = {
    .get_info              = aesxts_get_info,
    .create                = aesxts_create,
    .destroy               = aesxts_destroy,
    .reset                 = aesxts_reset,
    .rotate                = aesxts_rotate,
    .serialize_shareable   = aesxts_serialize_shareable,
    .deserialize_shareable = aesxts_deserialize_shareable,
    .compare_shareable     = aesxts_compare_shareable,
    .serialize_private     = aesxts_serialize_private,
    .deserialize_private   = aesxts_deserialize_private,
    .compare_private       = aesxts_compare_private,
    .encrypt               = aesxts_encrypt,
    .decrypt               = aesxts_decrypt,
    .last_error            = aesxts_last_error
};

int dvco_cipher_provider_get_api(const dvco_cipher_provider_api_t **out_api) {
    if (out_api == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_api = &g_aesxts_provider_api;
    return DVCO_CP_OK;
}

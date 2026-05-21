// SPDX-FileCopyrightText: 2026 Daniel Grazioli (graz)
// SPDX-FileCopyrightText: 2026 Ecosteer srl
// SPDX-License-Identifier: MIT
// ver: 1.0


// conf:
//   key=0x...                    optional, fixed initial key, must be 16 bytes
//
// rules:
//   - unsupported keys => error
//   - if key is omitted, rotate() must generate the runtime key
//   - nonce is generated internally per encrypt()
//   - AAD not supported

#include "ciphers/cipher_provider.h"
#define DVCO_CIPHER_ID  6u

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/rand.h>

#include "externals/ascon/asconaead128_ref/api.h"
#include "externals/ascon/asconaead128_ref/crypto_aead.h"

// --------------------------------------------------------------------------
// Ascon-AEAD128 provider - internal constants
// --------------------------------------------------------------------------

#define DVCO_ASCON_PROVIDER_NAME        "ascon-aead128"
#define DVCO_ASCON_PROVIDER_VERSION     "1.0"
#define DVCO_ASCON_PROVIDER_DESC        "DVCO Ascon-AEAD128 cipher provider (NIST SP 800-232, vendored CC0 ref core)"

#define DVCO_ASCON_KEY_LEN              ((size_t)CRYPTO_KEYBYTES)    // 16
#define DVCO_ASCON_NONCE_LEN            ((size_t)CRYPTO_NPUBBYTES)   // 16
#define DVCO_ASCON_TAG_LEN              ((size_t)CRYPTO_ABYTES)      // 16
#define DVCO_ASCON_SHAREABLE_HDR_LEN    2u                           // [key_len_be:2][key:key_len]
#define DVCO_ASCON_PAD_BLOCK_SIZE       1u

// --------------------------------------------------------------------------
// Opaque ctx implementation
// --------------------------------------------------------------------------

typedef struct ascon_cipher_ctx_s {
    dvco_selector_t cid;

    uint8_t key[DVCO_ASCON_KEY_LEN];
    size_t  key_len;       // 16 when active

    int     is_active;     // 0 = no usable key yet, 1 = ready

    char    last_err[160];
} ascon_cipher_ctx_t;

static ascon_cipher_ctx_t *ascon_ctx_from_opaque(dvco_cipher_ctx_t *ctx) {
    return (ascon_cipher_ctx_t *)ctx;
}

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

static void ascon_set_error(ascon_cipher_ctx_t *ctx, const char *msg) {
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

static void ascon_secure_zero(void *p, size_t n) {
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

static int ascon_key_len_is_valid(size_t key_len) {
    return key_len == DVCO_ASCON_KEY_LEN;
}

static int ascon_parse_hex_key(
    ascon_cipher_ctx_t *ctx,
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
        ascon_set_error(ctx, "invalid key format: expected 0x-prefixed hex string");
        return err_code_on_parse;
    }

    hex_len = len - 2u;
    if ((hex_len % 2u) != 0u) {
        ascon_set_error(ctx, "invalid hex key length");
        return err_code_on_parse;
    }

    out_len = hex_len / 2u;
    if (!ascon_key_len_is_valid(out_len)) {
        ascon_set_error(ctx, "hex key length must be exactly 16 bytes for Ascon-AEAD128");
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
            ascon_set_error(ctx, "invalid hex digit in key");
            return err_code_on_parse;
        }

        if (c_lo >= '0' && c_lo <= '9') {
            lo = c_lo - '0';
        } else if (c_lo >= 'a' && c_lo <= 'f') {
            lo = 10 + (c_lo - 'a');
        } else if (c_lo >= 'A' && c_lo <= 'F') {
            lo = 10 + (c_lo - 'A');
        } else {
            ascon_set_error(ctx, "invalid hex digit in key");
            return err_code_on_parse;
        }

        ctx->key[i] = (uint8_t)((hi << 4) | lo);
    }

    ctx->key_len = out_len;
    return DVCO_CP_OK;
}

static int ascon_load_cfg(
    ascon_cipher_ctx_t *ctx,
    const dvco_kv_t *cfg,
    size_t cfg_count
) {
    size_t i;
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
            ascon_set_error(ctx, "config contains NULL key/value");
            return DVCO_CP_ERR_CONFIG;
        }

        if (strcmp(k, "key") == 0) {
            int rc;

            rc = ascon_parse_hex_key(
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

        ascon_set_error(ctx, "unsupported config key");
        return DVCO_CP_ERR_CONFIG;
    }

    if (saw_key) {
        ctx->is_active = 1;
    }

    return DVCO_CP_OK;
}

// --------------------------------------------------------------------------
// Provider API implementation
// --------------------------------------------------------------------------

static int ascon_get_info(dvco_cipher_provider_info_t *out_info)
{
    if (out_info == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    memset(out_info, 0, sizeof(*out_info));

    out_info->abi_major         = DVCO_CIPHER_PROVIDER_API_VERSION_MAJOR;
    out_info->abi_minor         = DVCO_CIPHER_PROVIDER_API_VERSION_MINOR;
    out_info->provider_name     = DVCO_ASCON_PROVIDER_NAME;
    out_info->provider_version  = DVCO_ASCON_PROVIDER_VERSION;
    out_info->provider_desc     = DVCO_ASCON_PROVIDER_DESC;
    out_info->cid               = DVCO_CIPHER_ID;
    out_info->pad_apply         = false;
    out_info->pad_block_size    = DVCO_ASCON_PAD_BLOCK_SIZE;
    out_info->category_flags    = CRAG_PROVIDER_CATEGORY_SYMMETRIC;

    return DVCO_CP_OK;
}

static int ascon_create(const dvco_kv_t *cfg, size_t cfg_count, dvco_cipher_ctx_t **out_ctx) {
    ascon_cipher_ctx_t *ctx;
    int rc;

    if (out_ctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_ctx = NULL;

    ctx = (ascon_cipher_ctx_t *)calloc(1u, sizeof(*ctx));
    if (ctx == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }

    ctx->cid       = DVCO_CIPHER_ID;
    ctx->key_len   = 0u;
    ctx->is_active = 0;
    ascon_set_error(ctx, NULL);

    rc = ascon_load_cfg(ctx, cfg, cfg_count);
    if (rc != DVCO_CP_OK) {
        ascon_secure_zero(ctx, sizeof(*ctx));
        free(ctx);
        return rc;
    }

    *out_ctx = (dvco_cipher_ctx_t *)ctx;
    return DVCO_CP_OK;
}

static void ascon_destroy(dvco_cipher_ctx_t *ctx) {
    ascon_cipher_ctx_t *a = ascon_ctx_from_opaque(ctx);

    if (a == NULL) {
        return;
    }

    ascon_secure_zero(a, sizeof(*a));
    free(a);
}

static int ascon_reset(dvco_cipher_ctx_t *ctx) {
    ascon_cipher_ctx_t *a = ascon_ctx_from_opaque(ctx);

    if (a == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    ascon_set_error(a, NULL);
    return DVCO_CP_OK;
}

static int ascon_rotate(dvco_cipher_ctx_t *ctx) {
    ascon_cipher_ctx_t *a = ascon_ctx_from_opaque(ctx);

    if (a == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    ascon_set_error(a, NULL);
    ascon_secure_zero(a->key, sizeof(a->key));

    if (RAND_bytes(a->key, (int)DVCO_ASCON_KEY_LEN) != 1) {
        ascon_set_error(a, "RAND_bytes failed during rotate");
        a->key_len = 0u;
        a->is_active = 0;
        return DVCO_CP_ERR_CRYPTO;
    }

    a->key_len   = DVCO_ASCON_KEY_LEN;
    a->is_active = 1;

    return DVCO_CP_OK;
}

static int ascon_serialize_shareable(dvco_cipher_ctx_t *ctx, dvco_buf_t *out) {
    ascon_cipher_ctx_t *a = ascon_ctx_from_opaque(ctx);
    size_t needed;

    if (a == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active || !ascon_key_len_is_valid(a->key_len)) {
        ascon_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    needed = DVCO_ASCON_SHAREABLE_HDR_LEN + a->key_len;

    if (out->data == NULL) {
        out->len = needed;
        return DVCO_CP_OK;
    }

    if (out->cap < needed) {
        out->len = needed;
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    u16_to_be((uint16_t)a->key_len, &out->data[0]);
    memcpy(&out->data[DVCO_ASCON_SHAREABLE_HDR_LEN], a->key, a->key_len);
    out->len = needed;

    return DVCO_CP_OK;
}

static int ascon_deserialize_shareable(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len
) {
    ascon_cipher_ctx_t *a = ascon_ctx_from_opaque(ctx);
    uint16_t declared_len;
    size_t expected_len;

    if (a == NULL || in_data == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (in_len < DVCO_ASCON_SHAREABLE_HDR_LEN) {
        ascon_set_error(a, "shareable blob too short");
        return DVCO_CP_ERR_PARSE;
    }

    declared_len = u16_from_be(&in_data[0]);
    if (!ascon_key_len_is_valid((size_t)declared_len)) {
        ascon_set_error(a, "invalid Ascon key length in shareable blob");
        return DVCO_CP_ERR_PARSE;
    }

    expected_len = DVCO_ASCON_SHAREABLE_HDR_LEN + (size_t)declared_len;
    if (in_len != expected_len) {
        ascon_set_error(a, "shareable blob length mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    ascon_secure_zero(a->key, sizeof(a->key));
    memcpy(a->key, &in_data[DVCO_ASCON_SHAREABLE_HDR_LEN], (size_t)declared_len);
    a->key_len = (size_t)declared_len;
    a->is_active = 1;
    ascon_set_error(a, NULL);

    return DVCO_CP_OK;
}

static int ascon_compare_shareable(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    ascon_cipher_ctx_t *a = ascon_ctx_from_opaque(ctx);
    uint16_t declared_len;
    size_t expected_len;

    if (a == NULL || blob == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active || !ascon_key_len_is_valid(a->key_len)) {
        ascon_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (blob_len < DVCO_ASCON_SHAREABLE_HDR_LEN) {
        ascon_set_error(a, "shareable blob too short");
        return DVCO_CP_ERR_PARSE;
    }

    declared_len = u16_from_be(&blob[0]);
    if (!ascon_key_len_is_valid((size_t)declared_len)) {
        ascon_set_error(a, "invalid Ascon key length in shareable blob");
        return DVCO_CP_ERR_PARSE;
    }

    expected_len = DVCO_ASCON_SHAREABLE_HDR_LEN + (size_t)declared_len;
    if (blob_len != expected_len) {
        ascon_set_error(a, "shareable blob length mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    if ((size_t)declared_len != a->key_len) {
        ascon_set_error(a, "shareable key length mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    if (memcmp(&blob[DVCO_ASCON_SHAREABLE_HDR_LEN], a->key, a->key_len) != 0) {
        ascon_set_error(a, "shareable blob content mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    return DVCO_CP_OK;
}

static int ascon_serialize_private(dvco_cipher_ctx_t *ctx, dvco_buf_t *out) {
    return ascon_serialize_shareable(ctx, out);
}

static int ascon_deserialize_private(dvco_cipher_ctx_t *ctx, const uint8_t *in_data, size_t in_len) {
    return ascon_deserialize_shareable(ctx, in_data, in_len);
}

static int ascon_compare_private(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    return ascon_compare_shareable(ctx, blob, blob_len);
}

static int ascon_encrypt(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out
) {
    ascon_cipher_ctx_t *a = ascon_ctx_from_opaque(ctx);
    uint8_t nonce[DVCO_ASCON_NONCE_LEN];
    unsigned long long clen = 0u;
    size_t needed;
    size_t ct_off;
    int rc;

    if (a == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active || !ascon_key_len_is_valid(a->key_len)) {
        ascon_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if ((in_len > 0u) && (in_data == NULL)) {
        ascon_set_error(a, "encrypt input is NULL");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (aad != NULL || aad_len != 0u) {
        ascon_set_error(a, "AAD not supported by Ascon-AEAD128 provider v1");
        return DVCO_CP_ERR_NOT_SUPPORTED;
    }

    // Provider-owned frame:
    // [nonce_len:1][nonce:16][ciphertext:in_len][tag:16]
    needed = 1u + DVCO_ASCON_NONCE_LEN + in_len + DVCO_ASCON_TAG_LEN;

    if (out->data == NULL) {
        out->len = needed;
        return DVCO_CP_OK;
    }

    if (out->cap < needed) {
        out->len = needed;
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    if (RAND_bytes(nonce, (int)sizeof(nonce)) != 1) {
        ascon_set_error(a, "RAND_bytes failed");
        return DVCO_CP_ERR_CRYPTO;
    }

    out->data[0] = (uint8_t)DVCO_ASCON_NONCE_LEN;
    memcpy(&out->data[1], nonce, DVCO_ASCON_NONCE_LEN);
    ct_off = 1u + DVCO_ASCON_NONCE_LEN;

    rc = crypto_aead_encrypt(
        &out->data[ct_off],
        &clen,
        in_data,
        (unsigned long long)in_len,
        NULL,
        0u,
        NULL,
        nonce,
        a->key
    );

    ascon_secure_zero(nonce, sizeof(nonce));

    if (rc != 0) {
        ascon_set_error(a, "Ascon-AEAD128 encryption failed");
        return DVCO_CP_ERR_CRYPTO;
    }

    if (clen != (unsigned long long)(in_len + DVCO_ASCON_TAG_LEN)) {
        ascon_set_error(a, "unexpected Ascon-AEAD128 ciphertext length");
        return DVCO_CP_ERR_CRYPTO;
    }

    out->len = ct_off + (size_t)clen;
    return DVCO_CP_OK;
}

static int ascon_decrypt(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out
) {
    ascon_cipher_ctx_t *a = ascon_ctx_from_opaque(ctx);
    uint8_t nonce_len;
    const uint8_t *nonce;
    const uint8_t *ct_and_tag;
    size_t ct_and_tag_len;
    size_t needed;
    unsigned long long mlen = 0u;
    int rc;

    if (a == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active || !ascon_key_len_is_valid(a->key_len)) {
        ascon_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (in_data == NULL) {
        ascon_set_error(a, "decrypt input is NULL");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (aad != NULL || aad_len != 0u) {
        ascon_set_error(a, "AAD not supported by Ascon-AEAD128 provider v1");
        return DVCO_CP_ERR_NOT_SUPPORTED;
    }

    if (in_len < (1u + DVCO_ASCON_NONCE_LEN + DVCO_ASCON_TAG_LEN)) {
        ascon_set_error(a, "ciphertext too short");
        return DVCO_CP_ERR_PARSE;
    }

    nonce_len = in_data[0];
    if (nonce_len != DVCO_ASCON_NONCE_LEN) {
        ascon_set_error(a, "invalid nonce length");
        return DVCO_CP_ERR_PARSE;
    }

    nonce = &in_data[1];
    ct_and_tag = &in_data[1u + (size_t)nonce_len];
    ct_and_tag_len = in_len - 1u - (size_t)nonce_len;

    if (ct_and_tag_len < DVCO_ASCON_TAG_LEN) {
        ascon_set_error(a, "ciphertext/tag too short");
        return DVCO_CP_ERR_PARSE;
    }

    needed = ct_and_tag_len - DVCO_ASCON_TAG_LEN;

    if (out->data == NULL) {
        out->len = needed;
        return DVCO_CP_OK;
    }

    if (out->cap < needed) {
        out->len = needed;
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    rc = crypto_aead_decrypt(
        out->data,
        &mlen,
        NULL,
        ct_and_tag,
        (unsigned long long)ct_and_tag_len,
        NULL,
        0u,
        nonce,
        a->key
    );

    if (rc != 0) {
        ascon_set_error(a, "Ascon-AEAD128 authentication failed");
        return DVCO_CP_ERR_CRYPTO;
    }

    if (mlen != (unsigned long long)needed) {
        ascon_set_error(a, "unexpected Ascon-AEAD128 plaintext length");
        return DVCO_CP_ERR_CRYPTO;
    }

    out->len = (size_t)mlen;
    return DVCO_CP_OK;
}

static const char *ascon_last_error(dvco_cipher_ctx_t *ctx) {
    ascon_cipher_ctx_t *a = ascon_ctx_from_opaque(ctx);

    if (a == NULL) {
        return "invalid Ascon-AEAD128 provider context";
    }

    return a->last_err;
}

// --------------------------------------------------------------------------
// Provider vtable and plugin entry point
// --------------------------------------------------------------------------

static const dvco_cipher_provider_api_t g_ascon_provider_api = {
    .get_info              = ascon_get_info,
    .create                = ascon_create,
    .destroy               = ascon_destroy,
    .reset                 = ascon_reset,
    .rotate                = ascon_rotate,
    .serialize_shareable   = ascon_serialize_shareable,
    .deserialize_shareable = ascon_deserialize_shareable,
    .compare_shareable     = ascon_compare_shareable,
    .serialize_private     = ascon_serialize_private,
    .deserialize_private   = ascon_deserialize_private,
    .compare_private       = ascon_compare_private,
    .encrypt               = ascon_encrypt,
    .decrypt               = ascon_decrypt,
    .last_error            = ascon_last_error
};

int dvco_cipher_provider_get_api(const dvco_cipher_provider_api_t **out_api) {
    if (out_api == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_api = &g_ascon_provider_api;
    return DVCO_CP_OK;
}

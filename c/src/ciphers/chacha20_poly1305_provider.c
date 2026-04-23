// SPDX-FileCopyrightText: 2026 Daniel Grazioli (graz)
// SPDX-FileCopyrightText: 2026 Ecosteer srl
// SPDX-License-Identifier: MIT
// ver: 1.0

// conf:
//   key=0x...                    optional, fixed initial key, 32 bytes
//
// rules:
//   - unsupported keys => error
//   - if key is omitted, rotate() must generate the runtime key
//   - nonce is generated internally per encrypt()
//   - AAD not supported

#include "ciphers/cipher_provider.h"
#define DVCO_CIPHER_ID  4u

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

/* --------------------------------------------------------------------------
 * ChaCha20-Poly1305 provider - internal constants
 * -------------------------------------------------------------------------- */

#define DVCO_CHACHA20P1305_PROVIDER_NAME      "chacha20-poly1305"
#define DVCO_CHACHA20P1305_PROVIDER_VERSION   "1.0"
#define DVCO_CHACHA20P1305_PROVIDER_DESC      "DVCO ChaCha20-Poly1305 cipher provider (OpenSSL EVP)"

#define DVCO_CHACHA20P1305_KEY_LEN            32u
#define DVCO_CHACHA20P1305_NONCE_LEN          12u
#define DVCO_CHACHA20P1305_TAG_LEN            16u
#define DVCO_CHACHA20P1305_BLOCK_SIZE         1u
#define DVCO_CHACHA20P1305_SHAREABLE_HDR_LEN  2u    /* [key_len_be:2][key:key_len] */

/* --------------------------------------------------------------------------
 * Opaque ctx implementation
 * -------------------------------------------------------------------------- */

typedef struct chacha20p1305_cipher_ctx_s {
    dvco_selector_t cid;

    uint8_t key[DVCO_CHACHA20P1305_KEY_LEN];
    size_t  key_len;       /* always 32 when active */

    int     is_active;     /* 0 = no usable key yet, 1 = ready */

    char    last_err[160];
} chacha20p1305_cipher_ctx_t;

static chacha20p1305_cipher_ctx_t *chacha20p1305_ctx_from_opaque(dvco_cipher_ctx_t *ctx) {
    return (chacha20p1305_cipher_ctx_t *)ctx;
}

/* --------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------- */

static void chacha20p1305_set_error(chacha20p1305_cipher_ctx_t *ctx, const char *msg) {
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

static void chacha20p1305_secure_zero(void *p, size_t n) {
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

static int chacha20p1305_key_len_is_valid(size_t key_len) {
    return (key_len == DVCO_CHACHA20P1305_KEY_LEN);
}

static int chacha20p1305_parse_hex_key(
    chacha20p1305_cipher_ctx_t *ctx,
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
        chacha20p1305_set_error(ctx, "invalid key format: expected 0x-prefixed hex string");
        return err_code_on_parse;
    }

    hex_len = len - 2u;
    if ((hex_len % 2u) != 0u) {
        chacha20p1305_set_error(ctx, "invalid hex key length");
        return err_code_on_parse;
    }

    out_len = hex_len / 2u;
    if (!chacha20p1305_key_len_is_valid(out_len)) {
        chacha20p1305_set_error(ctx, "hex key length must be 32 bytes");
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
            chacha20p1305_set_error(ctx, "invalid hex digit in key");
            return err_code_on_parse;
        }

        if (c_lo >= '0' && c_lo <= '9') {
            lo = c_lo - '0';
        } else if (c_lo >= 'a' && c_lo <= 'f') {
            lo = 10 + (c_lo - 'a');
        } else if (c_lo >= 'A' && c_lo <= 'F') {
            lo = 10 + (c_lo - 'A');
        } else {
            chacha20p1305_set_error(ctx, "invalid hex digit in key");
            return err_code_on_parse;
        }

        ctx->key[i] = (uint8_t)((hi << 4) | lo);
    }

    ctx->key_len = out_len;
    return DVCO_CP_OK;
}

static int chacha20p1305_load_cfg(
    chacha20p1305_cipher_ctx_t *ctx,
    const dvco_kv_t *cfg,
    size_t cfg_count
) {
    size_t i;

    if (ctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    for (i = 0u; i < cfg_count; i++) {
        const char *k;
        const char *v;

        k = cfg[i].key;
        v = cfg[i].value;

        if (k == NULL || v == NULL) {
            chacha20p1305_set_error(ctx, "config contains NULL key/value");
            return DVCO_CP_ERR_CONFIG;
        }

        if (strcmp(k, "key") == 0) {
            int rc;

            rc = chacha20p1305_parse_hex_key(
                ctx,
                (const uint8_t *)v,
                strlen(v),
                DVCO_CP_ERR_CONFIG
            );
            if (rc != DVCO_CP_OK) {
                return rc;
            }

            ctx->is_active = 1;
            continue;
        }

        chacha20p1305_set_error(ctx, "unsupported config key");
        return DVCO_CP_ERR_CONFIG;
    }

    return DVCO_CP_OK;
}

/* --------------------------------------------------------------------------
 * Provider API implementation
 * -------------------------------------------------------------------------- */

static int chacha20p1305_get_info(dvco_cipher_provider_info_t *out_info)
{
    if (out_info == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    memset(out_info, 0, sizeof(*out_info));

    out_info->abi_major        = DVCO_CIPHER_PROVIDER_API_VERSION_MAJOR;
    out_info->abi_minor        = DVCO_CIPHER_PROVIDER_API_VERSION_MINOR;
    out_info->provider_name    = DVCO_CHACHA20P1305_PROVIDER_NAME;
    out_info->provider_version = DVCO_CHACHA20P1305_PROVIDER_VERSION;
    out_info->provider_desc    = DVCO_CHACHA20P1305_PROVIDER_DESC;
    out_info->cid              = DVCO_CIPHER_ID;
    out_info->pad_apply        = false;
    out_info->pad_block_size   = DVCO_CHACHA20P1305_BLOCK_SIZE;

    return DVCO_CP_OK;
}

static int chacha20p1305_create(const dvco_kv_t *cfg, size_t cfg_count, dvco_cipher_ctx_t **out_ctx) {
    chacha20p1305_cipher_ctx_t *ctx;
    int rc;

    if (out_ctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_ctx = NULL;

    ctx = (chacha20p1305_cipher_ctx_t *)calloc(1u, sizeof(*ctx));
    if (ctx == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }

    ctx->cid       = DVCO_CIPHER_ID;
    ctx->key_len   = 0u;
    ctx->is_active = 0;
    chacha20p1305_set_error(ctx, NULL);

    rc = chacha20p1305_load_cfg(ctx, cfg, cfg_count);
    if (rc != DVCO_CP_OK) {
        chacha20p1305_secure_zero(ctx, sizeof(*ctx));
        free(ctx);
        return rc;
    }

    *out_ctx = (dvco_cipher_ctx_t *)ctx;
    return DVCO_CP_OK;
}

static void chacha20p1305_destroy(dvco_cipher_ctx_t *ctx) {
    chacha20p1305_cipher_ctx_t *a = chacha20p1305_ctx_from_opaque(ctx);

    if (a == NULL) {
        return;
    }

    chacha20p1305_secure_zero(a, sizeof(*a));
    free(a);
}

static int chacha20p1305_reset(dvco_cipher_ctx_t *ctx) {
    chacha20p1305_cipher_ctx_t *a = chacha20p1305_ctx_from_opaque(ctx);

    if (a == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    chacha20p1305_set_error(a, NULL);
    return DVCO_CP_OK;
}

static int chacha20p1305_rotate(dvco_cipher_ctx_t *ctx) {
    chacha20p1305_cipher_ctx_t *a = chacha20p1305_ctx_from_opaque(ctx);

    if (a == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    chacha20p1305_set_error(a, NULL);

    chacha20p1305_secure_zero(a->key, sizeof(a->key));

    if (RAND_bytes(a->key, (int)DVCO_CHACHA20P1305_KEY_LEN) != 1) {
        chacha20p1305_set_error(a, "RAND_bytes failed during rotate");
        a->key_len = 0u;
        a->is_active = 0;
        return DVCO_CP_ERR_CRYPTO;
    }

    a->key_len   = DVCO_CHACHA20P1305_KEY_LEN;
    a->is_active = 1;

    return DVCO_CP_OK;
}

static int chacha20p1305_serialize_shareable(dvco_cipher_ctx_t *ctx, dvco_buf_t *out) {
    chacha20p1305_cipher_ctx_t *a = chacha20p1305_ctx_from_opaque(ctx);
    size_t needed;

    if (a == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active || !chacha20p1305_key_len_is_valid(a->key_len)) {
        chacha20p1305_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    needed = DVCO_CHACHA20P1305_SHAREABLE_HDR_LEN + a->key_len;

    if (out->data == NULL) {
        out->len = needed;
        return DVCO_CP_OK;
    }

    if (out->cap < needed) {
        out->len = needed;
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    u16_to_be((uint16_t)a->key_len, &out->data[0]);
    memcpy(&out->data[DVCO_CHACHA20P1305_SHAREABLE_HDR_LEN], a->key, a->key_len);
    out->len = needed;

    return DVCO_CP_OK;
}

static int chacha20p1305_deserialize_shareable(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len
) {
    chacha20p1305_cipher_ctx_t *a = chacha20p1305_ctx_from_opaque(ctx);
    uint16_t declared_len;
    size_t expected_len;

    if (a == NULL || in_data == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (in_len < DVCO_CHACHA20P1305_SHAREABLE_HDR_LEN) {
        chacha20p1305_set_error(a, "shareable blob too short");
        return DVCO_CP_ERR_PARSE;
    }

    declared_len = u16_from_be(&in_data[0]);
    if (!chacha20p1305_key_len_is_valid((size_t)declared_len)) {
        chacha20p1305_set_error(a, "invalid key length in shareable blob");
        return DVCO_CP_ERR_PARSE;
    }

    expected_len = DVCO_CHACHA20P1305_SHAREABLE_HDR_LEN + (size_t)declared_len;
    if (in_len != expected_len) {
        chacha20p1305_set_error(a, "shareable blob length mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    chacha20p1305_secure_zero(a->key, sizeof(a->key));
    memcpy(a->key, &in_data[DVCO_CHACHA20P1305_SHAREABLE_HDR_LEN], (size_t)declared_len);
    a->key_len = (size_t)declared_len;
    a->is_active = 1;
    chacha20p1305_set_error(a, NULL);

    return DVCO_CP_OK;
}

static int chacha20p1305_compare_shareable(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    chacha20p1305_cipher_ctx_t *a = chacha20p1305_ctx_from_opaque(ctx);
    uint16_t declared_len;
    size_t expected_len;

    if (a == NULL || blob == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active || !chacha20p1305_key_len_is_valid(a->key_len)) {
        chacha20p1305_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (blob_len < DVCO_CHACHA20P1305_SHAREABLE_HDR_LEN) {
        chacha20p1305_set_error(a, "shareable blob too short");
        return DVCO_CP_ERR_PARSE;
    }

    declared_len = u16_from_be(&blob[0]);
    if (!chacha20p1305_key_len_is_valid((size_t)declared_len)) {
        chacha20p1305_set_error(a, "invalid key length in shareable blob");
        return DVCO_CP_ERR_PARSE;
    }

    expected_len = DVCO_CHACHA20P1305_SHAREABLE_HDR_LEN + (size_t)declared_len;
    if (blob_len != expected_len) {
        chacha20p1305_set_error(a, "shareable blob length mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    if ((size_t)declared_len != a->key_len) {
        chacha20p1305_set_error(a, "shareable key length mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    if (memcmp(&blob[DVCO_CHACHA20P1305_SHAREABLE_HDR_LEN], a->key, a->key_len) != 0) {
        chacha20p1305_set_error(a, "shareable blob content mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    return DVCO_CP_OK;
}

static int chacha20p1305_serialize_private(dvco_cipher_ctx_t *ctx, dvco_buf_t *out) {
    return chacha20p1305_serialize_shareable(ctx, out);
}

static int chacha20p1305_deserialize_private(dvco_cipher_ctx_t *ctx, const uint8_t *in_data, size_t in_len) {
    return chacha20p1305_deserialize_shareable(ctx, in_data, in_len);
}

static int chacha20p1305_compare_private(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    return chacha20p1305_compare_shareable(ctx, blob, blob_len);
}

static int chacha20p1305_encrypt(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out
) {
    chacha20p1305_cipher_ctx_t *a = chacha20p1305_ctx_from_opaque(ctx);
    EVP_CIPHER_CTX *evp = NULL;
    uint8_t nonce[DVCO_CHACHA20P1305_NONCE_LEN];
    uint8_t tag[DVCO_CHACHA20P1305_TAG_LEN];
    size_t needed;
    int outl1 = 0;
    int outl2 = 0;
    int rc = DVCO_CP_ERR_CRYPTO;

    if (a == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active) {
        chacha20p1305_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if ((in_len > 0u) && (in_data == NULL)) {
        chacha20p1305_set_error(a, "encrypt input is NULL");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (aad != NULL || aad_len != 0u) {
        chacha20p1305_set_error(a, "AAD not supported by ChaCha20-Poly1305 provider");
        return DVCO_CP_ERR_NOT_SUPPORTED;
    }

    needed = 1u + DVCO_CHACHA20P1305_NONCE_LEN + in_len + DVCO_CHACHA20P1305_TAG_LEN;

    if (out->data == NULL) {
        out->len = needed;
        return DVCO_CP_OK;
    }

    if (out->cap < needed) {
        out->len = needed;
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    if (RAND_bytes(nonce, (int)sizeof(nonce)) != 1) {
        chacha20p1305_set_error(a, "RAND_bytes failed");
        return DVCO_CP_ERR_CRYPTO;
    }

    evp = EVP_CIPHER_CTX_new();
    if (evp == NULL) {
        chacha20p1305_set_error(a, "EVP_CIPHER_CTX_new failed");
        chacha20p1305_secure_zero(nonce, sizeof(nonce));
        return DVCO_CP_ERR_ALLOC;
    }

    if (EVP_EncryptInit_ex(evp, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) {
        chacha20p1305_set_error(a, "EVP_EncryptInit_ex(cipher) failed");
        goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_AEAD_SET_IVLEN, (int)DVCO_CHACHA20P1305_NONCE_LEN, NULL) != 1) {
        chacha20p1305_set_error(a, "EVP_CTRL_AEAD_SET_IVLEN failed");
        goto done;
    }

    if (EVP_EncryptInit_ex(evp, NULL, NULL, a->key, nonce) != 1) {
        chacha20p1305_set_error(a, "EVP_EncryptInit_ex(key/nonce) failed");
        goto done;
    }

    out->data[0] = (uint8_t)DVCO_CHACHA20P1305_NONCE_LEN;
    memcpy(&out->data[1], nonce, DVCO_CHACHA20P1305_NONCE_LEN);

    if (in_len > 0u) {
        if (EVP_EncryptUpdate(
                evp,
                &out->data[1u + DVCO_CHACHA20P1305_NONCE_LEN],
                &outl1,
                in_data,
                (int)in_len) != 1) {
            chacha20p1305_set_error(a, "EVP_EncryptUpdate failed");
            goto done;
        }
    }

    if (EVP_EncryptFinal_ex(
            evp,
            &out->data[1u + DVCO_CHACHA20P1305_NONCE_LEN + (size_t)outl1],
            &outl2) != 1) {
        chacha20p1305_set_error(a, "EVP_EncryptFinal_ex failed");
        goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(
            evp,
            EVP_CTRL_AEAD_GET_TAG,
            (int)DVCO_CHACHA20P1305_TAG_LEN,
            tag) != 1) {
        chacha20p1305_set_error(a, "EVP_CTRL_AEAD_GET_TAG failed");
        goto done;
    }

    memcpy(
        &out->data[1u + DVCO_CHACHA20P1305_NONCE_LEN + (size_t)outl1 + (size_t)outl2],
        tag,
        DVCO_CHACHA20P1305_TAG_LEN
    );

    out->len = 1u + DVCO_CHACHA20P1305_NONCE_LEN + (size_t)outl1 + (size_t)outl2 + DVCO_CHACHA20P1305_TAG_LEN;
    rc = DVCO_CP_OK;

done:
    if (evp != NULL) {
        EVP_CIPHER_CTX_free(evp);
    }
    chacha20p1305_secure_zero(nonce, sizeof(nonce));
    chacha20p1305_secure_zero(tag, sizeof(tag));
    return rc;
}

static int chacha20p1305_decrypt(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out
) {
    chacha20p1305_cipher_ctx_t *a = chacha20p1305_ctx_from_opaque(ctx);
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

    if (a == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active) {
        chacha20p1305_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (in_data == NULL) {
        chacha20p1305_set_error(a, "decrypt input is NULL");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (aad != NULL || aad_len != 0u) {
        chacha20p1305_set_error(a, "AAD not supported by ChaCha20-Poly1305 provider");
        return DVCO_CP_ERR_NOT_SUPPORTED;
    }

    if (in_len < (1u + DVCO_CHACHA20P1305_NONCE_LEN + DVCO_CHACHA20P1305_TAG_LEN)) {
        chacha20p1305_set_error(a, "ciphertext too short");
        return DVCO_CP_ERR_PARSE;
    }

    nonce_len = in_data[0];
    if (nonce_len != DVCO_CHACHA20P1305_NONCE_LEN) {
        chacha20p1305_set_error(a, "invalid nonce length");
        return DVCO_CP_ERR_PARSE;
    }

    nonce = &in_data[1];
    ct = &in_data[1u + (size_t)nonce_len];
    ct_len = in_len - 1u - (size_t)nonce_len - DVCO_CHACHA20P1305_TAG_LEN;
    tag = &in_data[in_len - DVCO_CHACHA20P1305_TAG_LEN];

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
        chacha20p1305_set_error(a, "EVP_CIPHER_CTX_new failed");
        return DVCO_CP_ERR_ALLOC;
    }

    if (EVP_DecryptInit_ex(evp, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) {
        chacha20p1305_set_error(a, "EVP_DecryptInit_ex(cipher) failed");
        goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_AEAD_SET_IVLEN, (int)DVCO_CHACHA20P1305_NONCE_LEN, NULL) != 1) {
        chacha20p1305_set_error(a, "EVP_CTRL_AEAD_SET_IVLEN failed");
        goto done;
    }

    if (EVP_DecryptInit_ex(evp, NULL, NULL, a->key, nonce) != 1) {
        chacha20p1305_set_error(a, "EVP_DecryptInit_ex(key/nonce) failed");
        goto done;
    }

    if (ct_len > 0u) {
        if (EVP_DecryptUpdate(
                evp,
                out->data,
                &outl1,
                ct,
                (int)ct_len) != 1) {
            chacha20p1305_set_error(a, "EVP_DecryptUpdate failed");
            goto done;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(
            evp,
            EVP_CTRL_AEAD_SET_TAG,
            (int)DVCO_CHACHA20P1305_TAG_LEN,
            (void *)tag) != 1) {
        chacha20p1305_set_error(a, "EVP_CTRL_AEAD_SET_TAG failed");
        goto done;
    }

    if (EVP_DecryptFinal_ex(
            evp,
            &out->data[(size_t)outl1],
            &outl2) != 1) {
        chacha20p1305_set_error(a, "EVP_DecryptFinal_ex failed (tag mismatch or corrupt ciphertext)");
        rc = DVCO_CP_ERR_CRYPTO;
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

static const char *chacha20p1305_last_error(dvco_cipher_ctx_t *ctx) {
    chacha20p1305_cipher_ctx_t *a = chacha20p1305_ctx_from_opaque(ctx);

    if (a == NULL) {
        return "invalid ChaCha20-Poly1305 provider context";
    }

    return a->last_err;
}

/* --------------------------------------------------------------------------
 * Provider vtable and plugin entry point
 * -------------------------------------------------------------------------- */

static const dvco_cipher_provider_api_t g_chacha20p1305_provider_api = {
    .get_info              = chacha20p1305_get_info,
    .create                = chacha20p1305_create,
    .destroy               = chacha20p1305_destroy,
    .reset                 = chacha20p1305_reset,
    .rotate                = chacha20p1305_rotate,
    .serialize_shareable   = chacha20p1305_serialize_shareable,
    .deserialize_shareable = chacha20p1305_deserialize_shareable,
    .compare_shareable     = chacha20p1305_compare_shareable,
    .serialize_private     = chacha20p1305_serialize_private,
    .deserialize_private   = chacha20p1305_deserialize_private,
    .compare_private       = chacha20p1305_compare_private,
    .encrypt               = chacha20p1305_encrypt,
    .decrypt               = chacha20p1305_decrypt,
    .last_error            = chacha20p1305_last_error
};

int dvco_cipher_provider_get_api(const dvco_cipher_provider_api_t **out_api) {
    if (out_api == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_api = &g_chacha20p1305_provider_api;
    return DVCO_CP_OK;
}

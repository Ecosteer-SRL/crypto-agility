// SPDX-FileCopyrightText: 2026 Daniel Grazioli (graz)
// SPDX-FileCopyrightText: 2026 Ecosteer srl
// SPDX-License-Identifier: MIT
// ver: 1.0

// conf:
//   keybits=128|192|256          optional, default=256
//   key=0x...                    optional, fixed initial key, must match keybits

#include "ciphers/cipher_provider.h"
#define DVCO_CIPHER_ID  2u

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

/* --------------------------------------------------------------------------
 * AES-CBC provider - internal constants
 * -------------------------------------------------------------------------- */

#define DVCO_AES_PROVIDER_NAME        "aes-cbc"
#define DVCO_AES_PROVIDER_VERSION     "3.0"
#define DVCO_AES_PROVIDER_DESC        "DVCO AES-CBC cipher provider (OpenSSL EVP)"

#define DVCO_AES_BLOCK_SIZE           16u
#define DVCO_AES_IV_LEN_CBC           16u
#define DVCO_AES_KEY_LEN_DEFAULT      32u   /* default = AES-256 */
#define DVCO_AES_SHAREABLE_HDR_LEN    2u    /* [key_len_be:2][key:key_len] */

/* --------------------------------------------------------------------------
 * Opaque ctx implementation
 * -------------------------------------------------------------------------- */

typedef struct aes_cipher_ctx_s {
    dvco_selector_t cid;

    uint8_t key[32];
    size_t  key_len;           /* 16 / 24 / 32 when active */
    size_t  pref_key_len;      /* desired rotate() output: 16 / 24 / 32 */

    int     is_active;         /* 0 = no usable key yet, 1 = ready */

    char    last_err[160];
} aes_cipher_ctx_t;

static aes_cipher_ctx_t *aes_ctx_from_opaque(dvco_cipher_ctx_t *ctx) {
    return (aes_cipher_ctx_t *)ctx;
}

/* --------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------- */

static void aes_set_error(aes_cipher_ctx_t *ctx, const char *msg) {
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

static void aes_secure_zero(void *p, size_t n) {
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

static int key_len_is_valid(size_t key_len) {
    return (key_len == 16u || key_len == 24u || key_len == 32u);
}

static size_t keybits_to_keylen(unsigned long keybits) {
    switch (keybits) {
        case 128ul: return 16u;
        case 192ul: return 24u;
        case 256ul: return 32u;
        default:    return 0u;
    }
}

static const EVP_CIPHER *aes_select_evp_cipher(const aes_cipher_ctx_t *ctx) {
    if (ctx == NULL) {
        return NULL;
    }

    switch (ctx->key_len) {
        case 16u: return EVP_aes_128_cbc();
        case 24u: return EVP_aes_192_cbc();
        case 32u: return EVP_aes_256_cbc();
        default:  return NULL;
    }
}

static int aes_apply_keybits_string(aes_cipher_ctx_t *ctx, const char *keybits_str) {
    unsigned long keybits;
    size_t key_len;

    if (ctx == NULL || keybits_str == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    keybits = strtoul(keybits_str, NULL, 0);
    key_len = keybits_to_keylen(keybits);

    if (key_len == 0u) {
        aes_set_error(ctx, "invalid keybits (use 128, 192 or 256)");
        return DVCO_CP_ERR_CONFIG;
    }

    ctx->pref_key_len = key_len;
    return DVCO_CP_OK;
}

static int aes_load_cfg(aes_cipher_ctx_t *ctx, const dvco_kv_t *cfg, size_t cfg_count) {
    size_t i;

    if (ctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    for (i = 0u; i < cfg_count; i++) {
        if (cfg[i].key == NULL || cfg[i].value == NULL) {
            continue;
        }

        if (strcmp(cfg[i].key, "keybits") == 0) {
            if (aes_apply_keybits_string(ctx, cfg[i].value) != DVCO_CP_OK) {
                return DVCO_CP_ERR_CONFIG;
            }
        } else {
            aes_set_error(ctx, "unknown config key for aes-cbc provider");
            return DVCO_CP_ERR_CONFIG;
        }
    }

    return DVCO_CP_OK;
}

/* --------------------------------------------------------------------------
 * Provider API implementation
 * -------------------------------------------------------------------------- */

static int aes_get_info(dvco_cipher_provider_info_t *out_info) 
{
    if (out_info == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    memset(out_info, 0, sizeof(*out_info));

    out_info->abi_major        = DVCO_CIPHER_PROVIDER_API_VERSION_MAJOR;
    out_info->abi_minor        = DVCO_CIPHER_PROVIDER_API_VERSION_MINOR;
    out_info->provider_name    = DVCO_AES_PROVIDER_NAME;
    out_info->provider_version = DVCO_AES_PROVIDER_VERSION;
    out_info->provider_desc    = DVCO_AES_PROVIDER_DESC;
    out_info->cid              = DVCO_CIPHER_ID;
    out_info->pad_apply       = false;  //  the cipher pad/unpad
    out_info->pad_block_size  = 16;
    return DVCO_CP_OK;
}

static int aes_create(const dvco_kv_t *cfg, size_t cfg_count, dvco_cipher_ctx_t **out_ctx) {
    aes_cipher_ctx_t *ctx;
    int rc;

    if (out_ctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_ctx = NULL;

    ctx = (aes_cipher_ctx_t *)calloc(1u, sizeof(*ctx));
    if (ctx == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }

    ctx->pref_key_len = DVCO_AES_KEY_LEN_DEFAULT;
    ctx->key_len      = 0u;
    ctx->is_active    = 0;
    aes_set_error(ctx, NULL);

    rc = aes_load_cfg(ctx, cfg, cfg_count);
    if (rc != DVCO_CP_OK) {
        aes_secure_zero(ctx, sizeof(*ctx));
        free(ctx);
        return rc;
    }

    *out_ctx = (dvco_cipher_ctx_t *)ctx;
    return DVCO_CP_OK;
}

static void aes_destroy(dvco_cipher_ctx_t *ctx) {
    aes_cipher_ctx_t *a = aes_ctx_from_opaque(ctx);

    if (a == NULL) {
        return;
    }

    aes_secure_zero(a, sizeof(*a));
    free(a);
}

static int aes_reset(dvco_cipher_ctx_t *ctx) {
    aes_cipher_ctx_t *a = aes_ctx_from_opaque(ctx);

    if (a == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    aes_set_error(a, NULL);
    return DVCO_CP_OK;
}

static int aes_rotate(dvco_cipher_ctx_t *ctx) {
    aes_cipher_ctx_t *a = aes_ctx_from_opaque(ctx);
    size_t key_len;

    if (a == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    aes_set_error(a, NULL);

    key_len = a->pref_key_len;
    if (!key_len_is_valid(key_len)) {
        aes_set_error(a, "invalid preferred AES key length");
        return DVCO_CP_ERR_BAD_STATE;
    }

    aes_secure_zero(a->key, sizeof(a->key));

    if (RAND_bytes(a->key, (int)key_len) != 1) {
        aes_set_error(a, "RAND_bytes failed during rotate");
        a->key_len = 0u;
        a->is_active = 0;
        return DVCO_CP_ERR_CRYPTO;
    }

    a->key_len   = key_len;
    a->is_active = 1;

    return DVCO_CP_OK;
}

static int aes_serialize_shareable(dvco_cipher_ctx_t *ctx, dvco_buf_t *out) {
    aes_cipher_ctx_t *a = aes_ctx_from_opaque(ctx);
    size_t needed;

    if (a == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active || !key_len_is_valid(a->key_len)) {
        aes_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    needed = DVCO_AES_SHAREABLE_HDR_LEN + a->key_len;

    if (out->data == NULL) {
        out->len = needed;
        return DVCO_CP_OK;
    }

    if (out->cap < needed) {
        out->len = needed;
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    u16_to_be((uint16_t)a->key_len, &out->data[0]);
    memcpy(&out->data[DVCO_AES_SHAREABLE_HDR_LEN], a->key, a->key_len);

    out->len = needed;
    return DVCO_CP_OK;
}


static int aes_deserialize_shareable(dvco_cipher_ctx_t *ctx, const uint8_t *in_data, size_t in_len) {
    aes_cipher_ctx_t *a = aes_ctx_from_opaque(ctx);
    uint16_t declared_len;

    if (a == NULL || in_data == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (in_len < DVCO_AES_SHAREABLE_HDR_LEN) {
        aes_set_error(a, "shareable blob too short");
        return DVCO_CP_ERR_PARSE;
    }

    declared_len = u16_from_be(&in_data[0]);
    if (!key_len_is_valid((size_t)declared_len)) {
        aes_set_error(a, "invalid AES key length in shareable blob");
        return DVCO_CP_ERR_PARSE;
    }

    if (in_len != (size_t)(DVCO_AES_SHAREABLE_HDR_LEN + declared_len)) {
        aes_set_error(a, "shareable blob length mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    memcpy(a->key, &in_data[DVCO_AES_SHAREABLE_HDR_LEN], (size_t)declared_len);
    a->key_len   = (size_t)declared_len;
    a->is_active = 1;

    /* pref_key_len is local config for future rotate(); do not overwrite it here. */

    return DVCO_CP_OK;
}

static int aes_compare_shareable(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    aes_cipher_ctx_t *a = aes_ctx_from_opaque(ctx);
    uint16_t declared_len;
    size_t expected_len;

    if (a == NULL || blob == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active || !key_len_is_valid(a->key_len)) {
        aes_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (blob_len < DVCO_AES_SHAREABLE_HDR_LEN) {
        aes_set_error(a, "shareable blob too short");
        return DVCO_CP_ERR_PARSE;
    }

    declared_len = u16_from_be(&blob[0]);
    if (!key_len_is_valid((size_t)declared_len)) {
        aes_set_error(a, "invalid AES key length in shareable blob");
        return DVCO_CP_ERR_PARSE;
    }

    expected_len = DVCO_AES_SHAREABLE_HDR_LEN + (size_t)declared_len;
    if (blob_len != expected_len) {
        aes_set_error(a, "shareable blob length mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    if ((size_t)declared_len != a->key_len) {
        aes_set_error(a, "shareable key length mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    if (memcmp(&blob[DVCO_AES_SHAREABLE_HDR_LEN], a->key, a->key_len) != 0) {
        aes_set_error(a, "shareable blob content mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    return DVCO_CP_OK;
}


static int aes_serialize_private(dvco_cipher_ctx_t *ctx, dvco_buf_t *out) {
    return aes_serialize_shareable(ctx, out);
}

static int aes_deserialize_private(dvco_cipher_ctx_t *ctx, const uint8_t *in_data, size_t in_len) {
    return aes_deserialize_shareable(ctx, in_data, in_len);
}

static int aes_compare_private(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    //  for the AES provider, private and shareable have the same format
    return aes_compare_shareable(ctx, blob, blob_len);
}


static int aes_encrypt(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out
) {
    aes_cipher_ctx_t *a = aes_ctx_from_opaque(ctx);
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *evp = NULL;
    uint8_t iv[DVCO_AES_IV_LEN_CBC];
    size_t needed;
    int outl1 = 0;
    int outl2 = 0;
    int rc = DVCO_CP_ERR_CRYPTO;

    if (a == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (!a->is_active) {
        aes_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if ((in_len > 0u) && (in_data == NULL)) {
        aes_set_error(a, "encrypt input is NULL");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (aad != NULL || aad_len != 0u) {
        aes_set_error(a, "AAD not supported by AES-CBC provider");
        return DVCO_CP_ERR_NOT_SUPPORTED;
    }

    cipher = aes_select_evp_cipher(a);
    if (cipher == NULL) {
        aes_set_error(a, "invalid AES state");
        return DVCO_CP_ERR_BAD_STATE;
    }

    /* [iv_len:1][iv:16][ciphertext:(in_len + up to one block padding)] */
    needed = 1u + DVCO_AES_IV_LEN_CBC + in_len + DVCO_AES_BLOCK_SIZE;

    if (out->data == NULL) {
        out->len = needed;
        return DVCO_CP_OK;
    }

    if (out->cap < needed) {
        out->len = needed;
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    if (RAND_bytes(iv, (int)sizeof(iv)) != 1) {
        aes_set_error(a, "RAND_bytes failed");
        return DVCO_CP_ERR_CRYPTO;
    }

    evp = EVP_CIPHER_CTX_new();
    if (evp == NULL) {
        aes_set_error(a, "EVP_CIPHER_CTX_new failed");
        return DVCO_CP_ERR_ALLOC;
    }

    if (EVP_EncryptInit_ex(evp, cipher, NULL, a->key, iv) != 1) {
        aes_set_error(a, "EVP_EncryptInit_ex failed");
        goto done;
    }

    out->data[0] = (uint8_t)DVCO_AES_IV_LEN_CBC;
    memcpy(&out->data[1], iv, DVCO_AES_IV_LEN_CBC);

    if (EVP_EncryptUpdate(
            evp,
            &out->data[1u + DVCO_AES_IV_LEN_CBC],
            &outl1,
            in_data,
            (int)in_len) != 1) {
        aes_set_error(a, "EVP_EncryptUpdate failed");
        goto done;
    }

    if (EVP_EncryptFinal_ex(
            evp,
            &out->data[1u + DVCO_AES_IV_LEN_CBC + (size_t)outl1],
            &outl2) != 1) {
        aes_set_error(a, "EVP_EncryptFinal_ex failed");
        goto done;
    }

    out->len = 1u + DVCO_AES_IV_LEN_CBC + (size_t)outl1 + (size_t)outl2;
    rc = DVCO_CP_OK;

done:
    if (evp != NULL) {
        EVP_CIPHER_CTX_free(evp);
    }
    aes_secure_zero(iv, sizeof(iv));
    return rc;
}


static int aes_decrypt(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out
) {
    aes_cipher_ctx_t *a = aes_ctx_from_opaque(ctx);
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *evp = NULL;
    uint8_t iv_len;
    const uint8_t *iv;
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
        aes_set_error(a, "provider is not active; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (in_data == NULL) {
        aes_set_error(a, "decrypt input is NULL");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (aad != NULL || aad_len != 0u) {
        aes_set_error(a, "AAD not supported by AES-CBC provider");
        return DVCO_CP_ERR_NOT_SUPPORTED;
    }

    cipher = aes_select_evp_cipher(a);
    if (cipher == NULL) {
        aes_set_error(a, "invalid AES state");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (in_len < (1u + DVCO_AES_IV_LEN_CBC)) {
        aes_set_error(a, "ciphertext too short");
        return DVCO_CP_ERR_PARSE;
    }

    iv_len = in_data[0];
    if (iv_len != DVCO_AES_IV_LEN_CBC) {
        aes_set_error(a, "invalid IV length");
        return DVCO_CP_ERR_PARSE;
    }

    iv = &in_data[1];
    ct = &in_data[1u + iv_len];
    ct_len = in_len - (1u + (size_t)iv_len);

    if (ct_len == 0u) {
        aes_set_error(a, "missing ciphertext");
        return DVCO_CP_ERR_PARSE;
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
        aes_set_error(a, "EVP_CIPHER_CTX_new failed");
        return DVCO_CP_ERR_ALLOC;
    }

    if (EVP_DecryptInit_ex(evp, cipher, NULL, a->key, iv) != 1) {
        aes_set_error(a, "EVP_DecryptInit_ex failed");
        goto done;
    }

    if (EVP_DecryptUpdate(
            evp,
            out->data,
            &outl1,
            ct,
            (int)ct_len) != 1) {
        aes_set_error(a, "EVP_DecryptUpdate failed");
        goto done;
    }

    if (EVP_DecryptFinal_ex(
            evp,
            &out->data[(size_t)outl1],
            &outl2) != 1) {
        aes_set_error(a, "EVP_DecryptFinal_ex failed");
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


static const char *aes_last_error(dvco_cipher_ctx_t *ctx) {
    aes_cipher_ctx_t *a = aes_ctx_from_opaque(ctx);

    if (a == NULL) {
        return NULL;
    }

    if (a->last_err[0] == '\0') {
        return NULL;
    }

    return a->last_err;
}

/* --------------------------------------------------------------------------
 * Static vtable
 * -------------------------------------------------------------------------- */

static const dvco_cipher_provider_api_t g_aes_provider_api = {
    .get_info              = aes_get_info,
    .create                = aes_create,
    .destroy               = aes_destroy,
    .reset                 = aes_reset,
    .rotate                = aes_rotate,
    .serialize_shareable   = aes_serialize_shareable,
    .deserialize_shareable = aes_deserialize_shareable,
    .compare_shareable     = aes_compare_shareable,
    .serialize_private     = aes_serialize_private,
    .deserialize_private   = aes_deserialize_private,
    .compare_private       = aes_compare_private,    
    .encrypt               = aes_encrypt,
    .decrypt               = aes_decrypt,
    .last_error            = aes_last_error
};

/* --------------------------------------------------------------------------
 * Plugin entry point
 * -------------------------------------------------------------------------- */

int dvco_cipher_provider_get_api(const dvco_cipher_provider_api_t **out_api) {
    if (out_api == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_api = &g_aes_provider_api;
    return DVCO_CP_OK;
}


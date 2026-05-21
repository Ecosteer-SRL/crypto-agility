// SPDX-FileCopyrightText: 2026 Daniel Grazioli (graz)
// SPDX-FileCopyrightText: 2026 Ecosteer srl
// SPDX-License-Identifier: MIT
// ver: 1.0

// conf:
//   keybits=2048|3072|4096        optional, default=2048
//
// rules:
//   - rotate() generates a new RSA recipient keypair
//   - serialize_shareable() exports the RSA public key in PEM format
//   - serialize_private() exports the RSA private key in PEM format
//   - deserialize_shareable() installs public/encrypt-capable state
//   - deserialize_private() installs private/decrypt-capable state
//   - encrypt() generates a fresh AES-256-GCM content-encryption key
//   - encrypt() wraps the AES key with RSA-OAEP-SHA256
//   - decrypt() unwraps the AES key with RSA-OAEP-SHA256
//   - ciphertext is provider-owned frame: header + wrapped key + nonce + tag + ciphertext
//   - payload size is not limited by RSA-OAEP because RSA is used only for key wrapping

#include "ciphers/cipher_provider.h"
#define DVCO_CIPHER_ID  4097u

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define DVCO_RSA_ENV_PROVIDER_NAME        "rsa-oaep-aes-gcm"
#define DVCO_RSA_ENV_PROVIDER_VERSION     "1.0"
#define DVCO_RSA_ENV_PROVIDER_DESC        "DVCO RSA-OAEP + AES-GCM asymmetric envelope cipher provider (OpenSSL EVP)"

#define DVCO_RSA_ENV_KEYBITS_DEFAULT      2048u

#define DVCO_RSA_ENV_AES_KEY_LEN          32u
#define DVCO_RSA_ENV_GCM_NONCE_LEN        12u
#define DVCO_RSA_ENV_GCM_TAG_LEN          16u

#define DVCO_RSA_ENV_FRAME_MAGIC_0        ((uint8_t)'R')
#define DVCO_RSA_ENV_FRAME_MAGIC_1        ((uint8_t)'O')
#define DVCO_RSA_ENV_FRAME_MAGIC_2        ((uint8_t)'A')
#define DVCO_RSA_ENV_FRAME_MAGIC_3        ((uint8_t)'G')
#define DVCO_RSA_ENV_FRAME_VERSION        1u
#define DVCO_RSA_ENV_FRAME_HEADER_LEN     17u

// --------------------------------------------------------------------------
// Opaque ctx implementation
// --------------------------------------------------------------------------

typedef struct rsa_env_cipher_ctx_s {
    dvco_selector_t cid;

    EVP_PKEY *pkey;
    unsigned int pref_keybits;

    int has_public;
    int has_private;

    char last_err[192];
} rsa_env_cipher_ctx_t;

static rsa_env_cipher_ctx_t *rsa_env_ctx_from_opaque(dvco_cipher_ctx_t *ctx) {
    return (rsa_env_cipher_ctx_t *)ctx;
}

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

static void rsa_env_set_error(rsa_env_cipher_ctx_t *ctx, const char *msg) {
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

static void rsa_env_secure_zero(void *p, size_t n) {
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n-- > 0u) {
        *vp++ = 0u;
    }
}

static int rsa_env_keybits_is_valid(unsigned int keybits) {
    return (keybits == 2048u || keybits == 3072u || keybits == 4096u);
}

static int rsa_env_parse_ulong(const char *s, unsigned long *out) {
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

static int rsa_env_apply_keybits_string(rsa_env_cipher_ctx_t *ctx, const char *keybits_str) {
    unsigned long keybits;
    int rc;

    if (ctx == NULL || keybits_str == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    rc = rsa_env_parse_ulong(keybits_str, &keybits);
    if (rc != DVCO_CP_OK) {
        rsa_env_set_error(ctx, "invalid keybits value");
        return DVCO_CP_ERR_CONFIG;
    }

    if (!rsa_env_keybits_is_valid((unsigned int)keybits)) {
        rsa_env_set_error(ctx, "invalid keybits (use 2048, 3072 or 4096)");
        return DVCO_CP_ERR_CONFIG;
    }

    ctx->pref_keybits = (unsigned int)keybits;
    return DVCO_CP_OK;
}

static int rsa_env_load_cfg(rsa_env_cipher_ctx_t *ctx, const dvco_kv_t *cfg, size_t cfg_count) {
    size_t i;

    if (ctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    for (i = 0u; i < cfg_count; i++) {
        if (cfg[i].key == NULL || cfg[i].value == NULL) {
            continue;
        }

        if (strcmp(cfg[i].key, "keybits") == 0) {
            if (rsa_env_apply_keybits_string(ctx, cfg[i].value) != DVCO_CP_OK) {
                return DVCO_CP_ERR_CONFIG;
            }
        } else {
            rsa_env_set_error(ctx, "unknown config key for rsa-oaep-aes-gcm provider");
            return DVCO_CP_ERR_CONFIG;
        }
    }

    return DVCO_CP_OK;
}

static void rsa_env_replace_key(rsa_env_cipher_ctx_t *ctx, EVP_PKEY *pkey, int has_private) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->pkey != NULL) {
        EVP_PKEY_free(ctx->pkey);
    }

    ctx->pkey = pkey;
    ctx->has_public = (pkey != NULL) ? 1 : 0;
    ctx->has_private = has_private ? 1 : 0;
}

static int rsa_env_copy_bio_to_out(rsa_env_cipher_ctx_t *ctx, BIO *bio, dvco_buf_t *out) {
    BUF_MEM *bptr = NULL;
    size_t needed;

    if (ctx == NULL || bio == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    BIO_get_mem_ptr(bio, &bptr);
    if (bptr == NULL || bptr->data == NULL) {
        rsa_env_set_error(ctx, "BIO_get_mem_ptr failed");
        return DVCO_CP_ERR_CRYPTO;
    }

    needed = bptr->length;

    if (out->data == NULL) {
        out->len = needed;
        return DVCO_CP_OK;
    }

    if (out->cap < needed) {
        out->len = needed;
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(out->data, bptr->data, needed);
    out->len = needed;
    return DVCO_CP_OK;
}

static int rsa_env_setup_oaep_ctx(rsa_env_cipher_ctx_t *ctx, EVP_PKEY_CTX *pctx) {
    if (ctx == NULL || pctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        rsa_env_set_error(ctx, "EVP_PKEY_CTX_set_rsa_padding failed");
        return DVCO_CP_ERR_CRYPTO;
    }

    if (EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256()) <= 0) {
        rsa_env_set_error(ctx, "EVP_PKEY_CTX_set_rsa_oaep_md failed");
        return DVCO_CP_ERR_CRYPTO;
    }

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) <= 0) {
        rsa_env_set_error(ctx, "EVP_PKEY_CTX_set_rsa_mgf1_md failed");
        return DVCO_CP_ERR_CRYPTO;
    }

    return DVCO_CP_OK;
}

static int rsa_env_blob_compare(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len) {
    if (a == NULL || b == NULL) {
        return 0;
    }

    if (a_len != b_len) {
        return 0;
    }

    if (a_len == 0u) {
        return 1;
    }

    return (memcmp(a, b, a_len) == 0) ? 1 : 0;
}

static void rsa_env_put_u16_be(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)((v >> 8) & 0xffu);
    p[1] = (uint8_t)(v & 0xffu);
}

static void rsa_env_put_u64_be(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)((v >> 56) & 0xffu);
    p[1] = (uint8_t)((v >> 48) & 0xffu);
    p[2] = (uint8_t)((v >> 40) & 0xffu);
    p[3] = (uint8_t)((v >> 32) & 0xffu);
    p[4] = (uint8_t)((v >> 24) & 0xffu);
    p[5] = (uint8_t)((v >> 16) & 0xffu);
    p[6] = (uint8_t)((v >> 8) & 0xffu);
    p[7] = (uint8_t)(v & 0xffu);
}

static uint16_t rsa_env_get_u16_be(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint64_t rsa_env_get_u64_be(const uint8_t *p) {
    return (((uint64_t)p[0]) << 56) |
           (((uint64_t)p[1]) << 48) |
           (((uint64_t)p[2]) << 40) |
           (((uint64_t)p[3]) << 32) |
           (((uint64_t)p[4]) << 24) |
           (((uint64_t)p[5]) << 16) |
           (((uint64_t)p[6]) << 8)  |
           ((uint64_t)p[7]);
}

static int rsa_env_frame_is_valid_magic(const uint8_t *p) {
    return p[0] == DVCO_RSA_ENV_FRAME_MAGIC_0 &&
           p[1] == DVCO_RSA_ENV_FRAME_MAGIC_1 &&
           p[2] == DVCO_RSA_ENV_FRAME_MAGIC_2 &&
           p[3] == DVCO_RSA_ENV_FRAME_MAGIC_3;
}

static int rsa_env_wrap_key(
    rsa_env_cipher_ctx_t *ctx,
    const uint8_t *key,
    size_t key_len,
    uint8_t *wrapped,
    size_t *wrapped_len
) {
    EVP_PKEY_CTX *pctx = NULL;
    int rc = DVCO_CP_ERR_CRYPTO;

    if (ctx == NULL || key == NULL || wrapped_len == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    pctx = EVP_PKEY_CTX_new(ctx->pkey, NULL);
    if (pctx == NULL) {
        rsa_env_set_error(ctx, "EVP_PKEY_CTX_new failed for RSA wrap");
        return DVCO_CP_ERR_ALLOC;
    }

    if (EVP_PKEY_encrypt_init(pctx) <= 0) {
        rsa_env_set_error(ctx, "EVP_PKEY_encrypt_init failed for RSA wrap");
        goto done;
    }

    rc = rsa_env_setup_oaep_ctx(ctx, pctx);
    if (rc != DVCO_CP_OK) {
        goto done;
    }

    if (EVP_PKEY_encrypt(pctx, wrapped, wrapped_len, key, key_len) <= 0) {
        rsa_env_set_error(ctx, "EVP_PKEY_encrypt failed for RSA wrap");
        rc = DVCO_CP_ERR_CRYPTO;
        goto done;
    }

    rc = DVCO_CP_OK;

done:
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
    return rc;
}

static int rsa_env_unwrap_key(
    rsa_env_cipher_ctx_t *ctx,
    const uint8_t *wrapped,
    size_t wrapped_len,
    uint8_t *key,
    size_t *key_len
) {
    EVP_PKEY_CTX *pctx = NULL;
    uint8_t *tmp = NULL;
    size_t tmp_len;
    size_t caller_cap;
    int rc = DVCO_CP_ERR_CRYPTO;

    if (ctx == NULL || wrapped == NULL || key == NULL || key_len == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    caller_cap = *key_len;
    if (caller_cap == 0u) {
        rsa_env_set_error(ctx, "RSA unwrap output buffer has zero capacity");
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    pctx = EVP_PKEY_CTX_new(ctx->pkey, NULL);
    if (pctx == NULL) {
        rsa_env_set_error(ctx, "EVP_PKEY_CTX_new failed for RSA unwrap");
        return DVCO_CP_ERR_ALLOC;
    }

    if (EVP_PKEY_decrypt_init(pctx) <= 0) {
        rsa_env_set_error(ctx, "EVP_PKEY_decrypt_init failed for RSA unwrap");
        goto done;
    }

    rc = rsa_env_setup_oaep_ctx(ctx, pctx);
    if (rc != DVCO_CP_OK) {
        goto done;
    }

    // Ask OpenSSL for the required temporary output size.
    // For RSA this is usually the modulus size, even if the final plaintext
    // is much smaller, for example a 32-byte AES key.
    tmp_len = 0u;
    if (EVP_PKEY_decrypt(pctx, NULL, &tmp_len, wrapped, wrapped_len) <= 0) {
        rsa_env_set_error(ctx, "EVP_PKEY_decrypt size query failed for RSA unwrap");
        rc = DVCO_CP_ERR_CRYPTO;
        goto done;
    }

    if (tmp_len == 0u) {
        rsa_env_set_error(ctx, "RSA unwrap reported zero output length");
        rc = DVCO_CP_ERR_CRYPTO;
        goto done;
    }

    tmp = (uint8_t *)malloc(tmp_len);
    if (tmp == NULL) {
        rsa_env_set_error(ctx, "temporary RSA unwrap buffer allocation failed");
        rc = DVCO_CP_ERR_ALLOC;
        goto done;
    }

    if (EVP_PKEY_decrypt(pctx, tmp, &tmp_len, wrapped, wrapped_len) <= 0) {
        rsa_env_set_error(ctx, "EVP_PKEY_decrypt failed for RSA unwrap");
        rc = DVCO_CP_ERR_CRYPTO;
        goto done;
    }

    if (tmp_len > caller_cap) {
        *key_len = tmp_len;
        rsa_env_set_error(ctx, "RSA unwrap output buffer too small");
        rc = DVCO_CP_ERR_BUFFER_TOO_SMALL;
        goto done;
    }

    memcpy(key, tmp, tmp_len);
    *key_len = tmp_len;
    rc = DVCO_CP_OK;

done:
    if (tmp != NULL) {
        rsa_env_secure_zero(tmp, tmp_len);
        free(tmp);
    }
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
    return rc;
}

static int rsa_env_aes_gcm_encrypt(
    rsa_env_cipher_ctx_t *ctx,
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *ciphertext,
    uint8_t *tag
) {
    EVP_CIPHER_CTX *gctx = NULL;
    int outl = 0;
    int tmplen = 0;
    int rc = DVCO_CP_ERR_CRYPTO;

    if (ctx == NULL || key == NULL || nonce == NULL || ciphertext == NULL || tag == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    gctx = EVP_CIPHER_CTX_new();
    if (gctx == NULL) {
        rsa_env_set_error(ctx, "EVP_CIPHER_CTX_new failed for AES-GCM encrypt");
        return DVCO_CP_ERR_ALLOC;
    }

    if (EVP_EncryptInit_ex(gctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        rsa_env_set_error(ctx, "EVP_EncryptInit_ex failed for AES-GCM");
        goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(gctx, EVP_CTRL_GCM_SET_IVLEN, (int)DVCO_RSA_ENV_GCM_NONCE_LEN, NULL) != 1) {
        rsa_env_set_error(ctx, "EVP_CIPHER_CTX_ctrl SET_IVLEN failed");
        goto done;
    }

    if (EVP_EncryptInit_ex(gctx, NULL, NULL, key, nonce) != 1) {
        rsa_env_set_error(ctx, "EVP_EncryptInit_ex key/nonce failed");
        goto done;
    }

    if (aad != NULL && aad_len > 0u) {
        if (aad_len > (size_t)INT32_MAX) {
            rsa_env_set_error(ctx, "AAD too large for AES-GCM");
            goto done;
        }

        if (EVP_EncryptUpdate(gctx, NULL, &outl, aad, (int)aad_len) != 1) {
            rsa_env_set_error(ctx, "EVP_EncryptUpdate AAD failed");
            goto done;
        }
    }

    if (in_len > 0u) {
        if (in_len > (size_t)INT32_MAX) {
            rsa_env_set_error(ctx, "plaintext too large for one AES-GCM update");
            goto done;
        }

        if (EVP_EncryptUpdate(gctx, ciphertext, &outl, in_data, (int)in_len) != 1) {
            rsa_env_set_error(ctx, "EVP_EncryptUpdate plaintext failed");
            goto done;
        }
    }

    if (EVP_EncryptFinal_ex(gctx, ciphertext + outl, &tmplen) != 1) {
        rsa_env_set_error(ctx, "EVP_EncryptFinal_ex failed");
        goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(gctx, EVP_CTRL_GCM_GET_TAG, (int)DVCO_RSA_ENV_GCM_TAG_LEN, tag) != 1) {
        rsa_env_set_error(ctx, "EVP_CIPHER_CTX_ctrl GET_TAG failed");
        goto done;
    }

    rc = DVCO_CP_OK;

done:
    if (gctx != NULL) {
        EVP_CIPHER_CTX_free(gctx);
    }
    return rc;
}

static int rsa_env_aes_gcm_decrypt(
    rsa_env_cipher_ctx_t *ctx,
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *tag,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *plaintext
) {
    EVP_CIPHER_CTX *gctx = NULL;
    int outl = 0;
    int tmplen = 0;
    int final_rc;
    int rc = DVCO_CP_ERR_CRYPTO;

    if (ctx == NULL || key == NULL || nonce == NULL || tag == NULL || plaintext == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    gctx = EVP_CIPHER_CTX_new();
    if (gctx == NULL) {
        rsa_env_set_error(ctx, "EVP_CIPHER_CTX_new failed for AES-GCM decrypt");
        return DVCO_CP_ERR_ALLOC;
    }

    if (EVP_DecryptInit_ex(gctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        rsa_env_set_error(ctx, "EVP_DecryptInit_ex failed for AES-GCM");
        goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(gctx, EVP_CTRL_GCM_SET_IVLEN, (int)DVCO_RSA_ENV_GCM_NONCE_LEN, NULL) != 1) {
        rsa_env_set_error(ctx, "EVP_CIPHER_CTX_ctrl SET_IVLEN failed");
        goto done;
    }

    if (EVP_DecryptInit_ex(gctx, NULL, NULL, key, nonce) != 1) {
        rsa_env_set_error(ctx, "EVP_DecryptInit_ex key/nonce failed");
        goto done;
    }

    if (aad != NULL && aad_len > 0u) {
        if (aad_len > (size_t)INT32_MAX) {
            rsa_env_set_error(ctx, "AAD too large for AES-GCM");
            goto done;
        }

        if (EVP_DecryptUpdate(gctx, NULL, &outl, aad, (int)aad_len) != 1) {
            rsa_env_set_error(ctx, "EVP_DecryptUpdate AAD failed");
            goto done;
        }
    }

    if (ciphertext_len > 0u) {
        if (ciphertext_len > (size_t)INT32_MAX) {
            rsa_env_set_error(ctx, "ciphertext too large for one AES-GCM update");
            goto done;
        }

        if (EVP_DecryptUpdate(gctx, plaintext, &outl, ciphertext, (int)ciphertext_len) != 1) {
            rsa_env_set_error(ctx, "EVP_DecryptUpdate ciphertext failed");
            goto done;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(gctx, EVP_CTRL_GCM_SET_TAG, (int)DVCO_RSA_ENV_GCM_TAG_LEN, (void *)tag) != 1) {
        rsa_env_set_error(ctx, "EVP_CIPHER_CTX_ctrl SET_TAG failed");
        goto done;
    }

    final_rc = EVP_DecryptFinal_ex(gctx, plaintext + outl, &tmplen);
    if (final_rc != 1) {
        rsa_env_set_error(ctx, "AES-GCM authentication failed");
        rc = DVCO_CP_ERR_CRYPTO;
        goto done;
    }

    rc = DVCO_CP_OK;

done:
    if (gctx != NULL) {
        EVP_CIPHER_CTX_free(gctx);
    }
    return rc;
}

// --------------------------------------------------------------------------
// Provider API implementation
// --------------------------------------------------------------------------

static int rsa_env_get_info(dvco_cipher_provider_info_t *out_info) {
    if (out_info == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    memset(out_info, 0, sizeof(*out_info));

    out_info->abi_major        = DVCO_CIPHER_PROVIDER_API_VERSION_MAJOR;
    out_info->abi_minor        = DVCO_CIPHER_PROVIDER_API_VERSION_MINOR;
    out_info->provider_name    = DVCO_RSA_ENV_PROVIDER_NAME;
    out_info->provider_version = DVCO_RSA_ENV_PROVIDER_VERSION;
    out_info->provider_desc    = DVCO_RSA_ENV_PROVIDER_DESC;
    out_info->cid              = DVCO_CIPHER_ID;
    out_info->pad_apply        = false;
    out_info->pad_block_size   = 1u;
    out_info->category_flags   = CRAG_PROVIDER_CATEGORY_ASYMMETRIC;

    return DVCO_CP_OK;
}

static int rsa_env_create(const dvco_kv_t *cfg, size_t cfg_count, dvco_cipher_ctx_t **out_ctx) {
    rsa_env_cipher_ctx_t *ctx;
    int rc;

    if (out_ctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_ctx = NULL;

    ctx = (rsa_env_cipher_ctx_t *)calloc(1u, sizeof(*ctx));
    if (ctx == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }

    ctx->cid = DVCO_CIPHER_ID;
    ctx->pkey = NULL;
    ctx->pref_keybits = DVCO_RSA_ENV_KEYBITS_DEFAULT;
    ctx->has_public = 0;
    ctx->has_private = 0;
    rsa_env_set_error(ctx, NULL);

    rc = rsa_env_load_cfg(ctx, cfg, cfg_count);
    if (rc != DVCO_CP_OK) {
        rsa_env_secure_zero(ctx, sizeof(*ctx));
        free(ctx);
        return rc;
    }

    *out_ctx = (dvco_cipher_ctx_t *)ctx;
    return DVCO_CP_OK;
}

static void rsa_env_destroy(dvco_cipher_ctx_t *ctx) {
    rsa_env_cipher_ctx_t *r = rsa_env_ctx_from_opaque(ctx);

    if (r == NULL) {
        return;
    }

    if (r->pkey != NULL) {
        EVP_PKEY_free(r->pkey);
        r->pkey = NULL;
    }

    rsa_env_secure_zero(r, sizeof(*r));
    free(r);
}

static int rsa_env_reset(dvco_cipher_ctx_t *ctx) {
    rsa_env_cipher_ctx_t *r = rsa_env_ctx_from_opaque(ctx);

    if (r == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    rsa_env_set_error(r, NULL);
    return DVCO_CP_OK;
}

static int rsa_env_rotate(dvco_cipher_ctx_t *ctx) {
    rsa_env_cipher_ctx_t *r = rsa_env_ctx_from_opaque(ctx);
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    int rc = DVCO_CP_ERR_CRYPTO;

    if (r == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    rsa_env_set_error(r, NULL);

    if (!rsa_env_keybits_is_valid(r->pref_keybits)) {
        rsa_env_set_error(r, "invalid preferred RSA keybits");
        return DVCO_CP_ERR_BAD_STATE;
    }

    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (kctx == NULL) {
        rsa_env_set_error(r, "EVP_PKEY_CTX_new_id failed");
        return DVCO_CP_ERR_ALLOC;
    }

    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        rsa_env_set_error(r, "EVP_PKEY_keygen_init failed");
        goto done;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, (int)r->pref_keybits) <= 0) {
        rsa_env_set_error(r, "EVP_PKEY_CTX_set_rsa_keygen_bits failed");
        goto done;
    }

    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        rsa_env_set_error(r, "EVP_PKEY_keygen failed");
        goto done;
    }

    rsa_env_replace_key(r, pkey, 1);
    pkey = NULL;
    rc = DVCO_CP_OK;

done:
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if (kctx != NULL) {
        EVP_PKEY_CTX_free(kctx);
    }
    return rc;
}

static int rsa_env_serialize_shareable(dvco_cipher_ctx_t *ctx, dvco_buf_t *out) {
    rsa_env_cipher_ctx_t *r = rsa_env_ctx_from_opaque(ctx);
    BIO *bio = NULL;
    int rc;

    if (r == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (r->pkey == NULL || !r->has_public) {
        rsa_env_set_error(r, "provider has no public key; rotate or deserialize first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        rsa_env_set_error(r, "BIO_new failed");
        return DVCO_CP_ERR_ALLOC;
    }

    if (PEM_write_bio_PUBKEY(bio, r->pkey) != 1) {
        rsa_env_set_error(r, "PEM_write_bio_PUBKEY failed");
        BIO_free(bio);
        return DVCO_CP_ERR_CRYPTO;
    }

    rc = rsa_env_copy_bio_to_out(r, bio, out);
    BIO_free(bio);
    return rc;
}

static int rsa_env_deserialize_shareable(dvco_cipher_ctx_t *ctx, const uint8_t *in_data, size_t in_len) {
    rsa_env_cipher_ctx_t *r = rsa_env_ctx_from_opaque(ctx);
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;

    if (r == NULL || in_data == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (in_len == 0u || in_len > (size_t)INT32_MAX) {
        rsa_env_set_error(r, "invalid public key blob length");
        return DVCO_CP_ERR_PARSE;
    }

    bio = BIO_new_mem_buf((const void *)in_data, (int)in_len);
    if (bio == NULL) {
        rsa_env_set_error(r, "BIO_new_mem_buf failed");
        return DVCO_CP_ERR_ALLOC;
    }

    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (pkey == NULL) {
        rsa_env_set_error(r, "PEM_read_bio_PUBKEY failed");
        return DVCO_CP_ERR_PARSE;
    }

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        EVP_PKEY_free(pkey);
        rsa_env_set_error(r, "public key is not RSA");
        return DVCO_CP_ERR_PARSE;
    }

    rsa_env_replace_key(r, pkey, 0);
    return DVCO_CP_OK;
}

static int rsa_env_compare_shareable(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    rsa_env_cipher_ctx_t *r = rsa_env_ctx_from_opaque(ctx);
    dvco_buf_t tmp;
    uint8_t *buf = NULL;
    int rc;

    if (r == NULL || blob == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    memset(&tmp, 0, sizeof(tmp));
    rc = rsa_env_serialize_shareable(ctx, &tmp);
    if (rc != DVCO_CP_OK) {
        return rc;
    }

    buf = (uint8_t *)malloc(tmp.len);
    if (buf == NULL) {
        rsa_env_set_error(r, "temporary compare buffer allocation failed");
        return DVCO_CP_ERR_ALLOC;
    }

    tmp.data = buf;
    tmp.cap = tmp.len;
    rc = rsa_env_serialize_shareable(ctx, &tmp);
    if (rc == DVCO_CP_OK) {
        rc = rsa_env_blob_compare(tmp.data, tmp.len, blob, blob_len) ? DVCO_CP_OK : DVCO_CP_ERR_PARSE;
        if (rc != DVCO_CP_OK) {
            rsa_env_set_error(r, "shareable blob content mismatch");
        }
    }

    rsa_env_secure_zero(buf, tmp.cap);
    free(buf);
    return rc;
}

static int rsa_env_serialize_private(dvco_cipher_ctx_t *ctx, dvco_buf_t *out) {
    rsa_env_cipher_ctx_t *r = rsa_env_ctx_from_opaque(ctx);
    BIO *bio = NULL;
    int rc;

    if (r == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (r->pkey == NULL || !r->has_private) {
        rsa_env_set_error(r, "provider has no private key; rotate or deserialize_private first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        rsa_env_set_error(r, "BIO_new failed");
        return DVCO_CP_ERR_ALLOC;
    }

    if (PEM_write_bio_PrivateKey(bio, r->pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        rsa_env_set_error(r, "PEM_write_bio_PrivateKey failed");
        BIO_free(bio);
        return DVCO_CP_ERR_CRYPTO;
    }

    rc = rsa_env_copy_bio_to_out(r, bio, out);
    BIO_free(bio);
    return rc;
}

static int rsa_env_deserialize_private(dvco_cipher_ctx_t *ctx, const uint8_t *in_data, size_t in_len) {
    rsa_env_cipher_ctx_t *r = rsa_env_ctx_from_opaque(ctx);
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;

    if (r == NULL || in_data == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (in_len == 0u || in_len > (size_t)INT32_MAX) {
        rsa_env_set_error(r, "invalid private key blob length");
        return DVCO_CP_ERR_PARSE;
    }

    bio = BIO_new_mem_buf((const void *)in_data, (int)in_len);
    if (bio == NULL) {
        rsa_env_set_error(r, "BIO_new_mem_buf failed");
        return DVCO_CP_ERR_ALLOC;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (pkey == NULL) {
        rsa_env_set_error(r, "PEM_read_bio_PrivateKey failed");
        return DVCO_CP_ERR_PARSE;
    }

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        EVP_PKEY_free(pkey);
        rsa_env_set_error(r, "private key is not RSA");
        return DVCO_CP_ERR_PARSE;
    }

    rsa_env_replace_key(r, pkey, 1);
    return DVCO_CP_OK;
}

static int rsa_env_compare_private(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    rsa_env_cipher_ctx_t *r = rsa_env_ctx_from_opaque(ctx);
    dvco_buf_t tmp;
    uint8_t *buf = NULL;
    int rc;

    if (r == NULL || blob == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    memset(&tmp, 0, sizeof(tmp));
    rc = rsa_env_serialize_private(ctx, &tmp);
    if (rc != DVCO_CP_OK) {
        return rc;
    }

    buf = (uint8_t *)malloc(tmp.len);
    if (buf == NULL) {
        rsa_env_set_error(r, "temporary compare buffer allocation failed");
        return DVCO_CP_ERR_ALLOC;
    }

    tmp.data = buf;
    tmp.cap = tmp.len;
    rc = rsa_env_serialize_private(ctx, &tmp);
    if (rc == DVCO_CP_OK) {
        rc = rsa_env_blob_compare(tmp.data, tmp.len, blob, blob_len) ? DVCO_CP_OK : DVCO_CP_ERR_PARSE;
        if (rc != DVCO_CP_OK) {
            rsa_env_set_error(r, "private blob content mismatch");
        }
    }

    rsa_env_secure_zero(buf, tmp.cap);
    free(buf);
    return rc;
}

static int rsa_env_encrypt(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out
) {
    rsa_env_cipher_ctx_t *r = rsa_env_ctx_from_opaque(ctx);
    uint8_t aes_key[DVCO_RSA_ENV_AES_KEY_LEN];
    uint8_t nonce[DVCO_RSA_ENV_GCM_NONCE_LEN];
    uint8_t tag[DVCO_RSA_ENV_GCM_TAG_LEN];
    uint8_t *wrapped = NULL;
    uint8_t *ciphertext = NULL;
    size_t wrapped_cap;
    size_t wrapped_len;
    size_t needed;
    uint8_t *p;
    int rc = DVCO_CP_ERR_CRYPTO;

    if (r == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (r->pkey == NULL || !r->has_public) {
        rsa_env_set_error(r, "provider has no public key; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if ((in_len > 0u) && (in_data == NULL)) {
        rsa_env_set_error(r, "encrypt input is NULL");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    wrapped_cap = (size_t)EVP_PKEY_size(r->pkey);
    if (wrapped_cap == 0u || wrapped_cap > 65535u) {
        rsa_env_set_error(r, "invalid RSA wrapped key size");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (in_len > (SIZE_MAX - DVCO_RSA_ENV_FRAME_HEADER_LEN - wrapped_cap - DVCO_RSA_ENV_GCM_NONCE_LEN - DVCO_RSA_ENV_GCM_TAG_LEN)) {
        rsa_env_set_error(r, "ciphertext frame size overflow");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    needed = DVCO_RSA_ENV_FRAME_HEADER_LEN +
             wrapped_cap +
             DVCO_RSA_ENV_GCM_NONCE_LEN +
             DVCO_RSA_ENV_GCM_TAG_LEN +
             in_len;

    if (out->data == NULL) {
        out->len = needed;
        return DVCO_CP_OK;
    }

    if (out->cap < needed) {
        out->len = needed;
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    wrapped = (uint8_t *)malloc(wrapped_cap);
    if (wrapped == NULL) {
        rsa_env_set_error(r, "wrapped key buffer allocation failed");
        return DVCO_CP_ERR_ALLOC;
    }

    ciphertext = (uint8_t *)malloc((in_len > 0u) ? in_len : 1u);
    if (ciphertext == NULL) {
        rsa_env_set_error(r, "ciphertext buffer allocation failed");
        rc = DVCO_CP_ERR_ALLOC;
        goto done;
    }

    if (RAND_bytes(aes_key, (int)sizeof(aes_key)) != 1) {
        rsa_env_set_error(r, "RAND_bytes failed for AES key");
        goto done;
    }

    if (RAND_bytes(nonce, (int)sizeof(nonce)) != 1) {
        rsa_env_set_error(r, "RAND_bytes failed for AES-GCM nonce");
        goto done;
    }

    rc = rsa_env_aes_gcm_encrypt(
        r,
        aes_key,
        nonce,
        in_data,
        in_len,
        aad,
        aad_len,
        ciphertext,
        tag
    );
    if (rc != DVCO_CP_OK) {
        goto done;
    }

    wrapped_len = wrapped_cap;
    rc = rsa_env_wrap_key(r, aes_key, sizeof(aes_key), wrapped, &wrapped_len);
    if (rc != DVCO_CP_OK) {
        goto done;
    }

    if (wrapped_len != wrapped_cap || wrapped_len > 65535u) {
        rsa_env_set_error(r, "unexpected RSA wrapped key length");
        rc = DVCO_CP_ERR_CRYPTO;
        goto done;
    }

    needed = DVCO_RSA_ENV_FRAME_HEADER_LEN +
             wrapped_len +
             DVCO_RSA_ENV_GCM_NONCE_LEN +
             DVCO_RSA_ENV_GCM_TAG_LEN +
             in_len;

    if (out->cap < needed) {
        out->len = needed;
        rc = DVCO_CP_ERR_BUFFER_TOO_SMALL;
        goto done;
    }

    p = out->data;
    p[0] = DVCO_RSA_ENV_FRAME_MAGIC_0;
    p[1] = DVCO_RSA_ENV_FRAME_MAGIC_1;
    p[2] = DVCO_RSA_ENV_FRAME_MAGIC_2;
    p[3] = DVCO_RSA_ENV_FRAME_MAGIC_3;
    p[4] = DVCO_RSA_ENV_FRAME_VERSION;
    rsa_env_put_u16_be(p + 5, (uint16_t)wrapped_len);
    p[7] = (uint8_t)DVCO_RSA_ENV_GCM_NONCE_LEN;
    p[8] = (uint8_t)DVCO_RSA_ENV_GCM_TAG_LEN;
    rsa_env_put_u64_be(p + 9, (uint64_t)in_len);
    p += DVCO_RSA_ENV_FRAME_HEADER_LEN;

    memcpy(p, wrapped, wrapped_len);
    p += wrapped_len;

    memcpy(p, nonce, DVCO_RSA_ENV_GCM_NONCE_LEN);
    p += DVCO_RSA_ENV_GCM_NONCE_LEN;

    memcpy(p, tag, DVCO_RSA_ENV_GCM_TAG_LEN);
    p += DVCO_RSA_ENV_GCM_TAG_LEN;

    if (in_len > 0u) {
        memcpy(p, ciphertext, in_len);
    }

    out->len = needed;
    rc = DVCO_CP_OK;

done:
    rsa_env_secure_zero(aes_key, sizeof(aes_key));
    rsa_env_secure_zero(nonce, sizeof(nonce));
    rsa_env_secure_zero(tag, sizeof(tag));

    if (wrapped != NULL) {
        rsa_env_secure_zero(wrapped, wrapped_cap);
        free(wrapped);
    }

    if (ciphertext != NULL) {
        rsa_env_secure_zero(ciphertext, (in_len > 0u) ? in_len : 1u);
        free(ciphertext);
    }

    return rc;
}

static int rsa_env_decrypt(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out
) {
    rsa_env_cipher_ctx_t *r = rsa_env_ctx_from_opaque(ctx);
    const uint8_t *p;
    const uint8_t *wrapped;
    const uint8_t *nonce;
    const uint8_t *tag;
    const uint8_t *ciphertext;
    uint16_t wrapped_len;
    uint8_t nonce_len;
    uint8_t tag_len;
    uint64_t ciphertext_len_u64;
    size_t ciphertext_len;
    size_t min_len;
    uint8_t aes_key[DVCO_RSA_ENV_AES_KEY_LEN];
    size_t aes_key_len;
    int rc = DVCO_CP_ERR_CRYPTO;

    if (r == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (r->pkey == NULL || !r->has_private) {
        rsa_env_set_error(r, "provider has no private key; rotate or deserialize_private first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (in_data == NULL) {
        rsa_env_set_error(r, "decrypt input is NULL");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (in_len < DVCO_RSA_ENV_FRAME_HEADER_LEN) {
        rsa_env_set_error(r, "ciphertext frame too short");
        return DVCO_CP_ERR_PARSE;
    }

    p = in_data;

    if (!rsa_env_frame_is_valid_magic(p)) {
        rsa_env_set_error(r, "invalid ciphertext frame magic");
        return DVCO_CP_ERR_PARSE;
    }

    if (p[4] != DVCO_RSA_ENV_FRAME_VERSION) {
        rsa_env_set_error(r, "unsupported ciphertext frame version");
        return DVCO_CP_ERR_PARSE;
    }

    wrapped_len = rsa_env_get_u16_be(p + 5);
    nonce_len = p[7];
    tag_len = p[8];
    ciphertext_len_u64 = rsa_env_get_u64_be(p + 9);

    if (nonce_len != DVCO_RSA_ENV_GCM_NONCE_LEN || tag_len != DVCO_RSA_ENV_GCM_TAG_LEN) {
        rsa_env_set_error(r, "unsupported AES-GCM nonce or tag length");
        return DVCO_CP_ERR_PARSE;
    }

    if (ciphertext_len_u64 > (uint64_t)SIZE_MAX) {
        rsa_env_set_error(r, "ciphertext length too large");
        return DVCO_CP_ERR_PARSE;
    }

    ciphertext_len = (size_t)ciphertext_len_u64;

    if (wrapped_len == 0u) {
        rsa_env_set_error(r, "wrapped key length is zero");
        return DVCO_CP_ERR_PARSE;
    }

    if (ciphertext_len > (SIZE_MAX - DVCO_RSA_ENV_FRAME_HEADER_LEN - (size_t)wrapped_len - (size_t)nonce_len - (size_t)tag_len)) {
        rsa_env_set_error(r, "ciphertext frame length overflow");
        return DVCO_CP_ERR_PARSE;
    }

    min_len = DVCO_RSA_ENV_FRAME_HEADER_LEN +
              (size_t)wrapped_len +
              (size_t)nonce_len +
              (size_t)tag_len +
              ciphertext_len;

    if (in_len != min_len) {
        rsa_env_set_error(r, "ciphertext frame length mismatch");
        return DVCO_CP_ERR_PARSE;
    }

    if (out->data == NULL) {
        out->len = ciphertext_len;
        return DVCO_CP_OK;
    }

    if (out->cap < ciphertext_len) {
        out->len = ciphertext_len;
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    p = in_data + DVCO_RSA_ENV_FRAME_HEADER_LEN;
    wrapped = p;
    p += wrapped_len;

    nonce = p;
    p += nonce_len;

    tag = p;
    p += tag_len;

    ciphertext = p;

    aes_key_len = sizeof(aes_key);
    rc = rsa_env_unwrap_key(r, wrapped, (size_t)wrapped_len, aes_key, &aes_key_len);
    if (rc != DVCO_CP_OK) {
        goto done;
    }

    if (aes_key_len != DVCO_RSA_ENV_AES_KEY_LEN) {
        rsa_env_set_error(r, "unexpected unwrapped AES key length");
        rc = DVCO_CP_ERR_CRYPTO;
        goto done;
    }

    rc = rsa_env_aes_gcm_decrypt(
        r,
        aes_key,
        nonce,
        ciphertext,
        ciphertext_len,
        tag,
        aad,
        aad_len,
        out->data
    );
    if (rc != DVCO_CP_OK) {
        goto done;
    }

    out->len = ciphertext_len;
    rc = DVCO_CP_OK;

done:
    rsa_env_secure_zero(aes_key, sizeof(aes_key));
    return rc;
}

static const char *rsa_env_last_error(dvco_cipher_ctx_t *ctx) {
    rsa_env_cipher_ctx_t *r = rsa_env_ctx_from_opaque(ctx);

    if (r == NULL) {
        return NULL;
    }

    if (r->last_err[0] == '\0') {
        return NULL;
    }

    return r->last_err;
}

// --------------------------------------------------------------------------
// Static vtable
// --------------------------------------------------------------------------

static const dvco_cipher_provider_api_t g_rsa_env_provider_api = {
    .get_info              = rsa_env_get_info,
    .create                = rsa_env_create,
    .destroy               = rsa_env_destroy,
    .reset                 = rsa_env_reset,
    .rotate                = rsa_env_rotate,
    .serialize_shareable   = rsa_env_serialize_shareable,
    .deserialize_shareable = rsa_env_deserialize_shareable,
    .compare_shareable     = rsa_env_compare_shareable,
    .serialize_private     = rsa_env_serialize_private,
    .deserialize_private   = rsa_env_deserialize_private,
    .compare_private       = rsa_env_compare_private,
    .encrypt               = rsa_env_encrypt,
    .decrypt               = rsa_env_decrypt,
    .last_error            = rsa_env_last_error
};

// --------------------------------------------------------------------------
// Plugin entry point
// --------------------------------------------------------------------------

int dvco_cipher_provider_get_api(const dvco_cipher_provider_api_t **out_api) {
    if (out_api == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_api = &g_rsa_env_provider_api;
    return DVCO_CP_OK;
}

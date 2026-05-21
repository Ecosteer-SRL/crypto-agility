// SPDX-FileCopyrightText: 2026 Daniel Grazioli (graz)
// SPDX-FileCopyrightText: 2026 Ecosteer srl
// SPDX-License-Identifier: MIT
// ver: 1.0

// conf:
//   keybits=2048|3072|4096        optional, default=2048
//
// rules:
//   - rotate() generates a new RSA keypair
//   - serialize_shareable() exports the public key in PEM format
//   - serialize_private() exports the private key in PEM format
//   - deserialize_shareable() installs public/encrypt-capable state
//   - deserialize_private() installs private/decrypt-capable state
//   - RSA-OAEP uses SHA-256 for OAEP and MGF1
//   - payload size is limited by RSA key size and OAEP overhead

#include "ciphers/cipher_provider.h"
#define DVCO_CIPHER_ID  4096u

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

// --------------------------------------------------------------------------
// RSA-OAEP provider - internal constants
// --------------------------------------------------------------------------

#define DVCO_RSA_PROVIDER_NAME        "rsa-oaep"
#define DVCO_RSA_PROVIDER_VERSION     "1.0"
#define DVCO_RSA_PROVIDER_DESC        "DVCO RSA-OAEP asymmetric cipher provider (OpenSSL EVP)"

#define DVCO_RSA_KEYBITS_DEFAULT      2048u
#define DVCO_RSA_KEYBITS_MIN          2048u
#define DVCO_RSA_KEYBITS_MAX          4096u

// --------------------------------------------------------------------------
// Opaque ctx implementation
// --------------------------------------------------------------------------

typedef struct rsa_cipher_ctx_s {
    dvco_selector_t cid;

    EVP_PKEY *pkey;
    unsigned int pref_keybits;

    int has_public;
    int has_private;

    char last_err[160];
} rsa_cipher_ctx_t;

static rsa_cipher_ctx_t *rsa_ctx_from_opaque(dvco_cipher_ctx_t *ctx) {
    return (rsa_cipher_ctx_t *)ctx;
}

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

static void rsa_set_error(rsa_cipher_ctx_t *ctx, const char *msg) {
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

static void rsa_secure_zero(void *p, size_t n) {
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n-- > 0u) {
        *vp++ = 0u;
    }
}

static int rsa_keybits_is_valid(unsigned int keybits) {
    return (keybits == 2048u || keybits == 3072u || keybits == 4096u);
}

static int rsa_parse_ulong(const char *s, unsigned long *out) {
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

static int rsa_apply_keybits_string(rsa_cipher_ctx_t *ctx, const char *keybits_str) {
    unsigned long keybits;
    int rc;

    if (ctx == NULL || keybits_str == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    rc = rsa_parse_ulong(keybits_str, &keybits);
    if (rc != DVCO_CP_OK) {
        rsa_set_error(ctx, "invalid keybits value");
        return DVCO_CP_ERR_CONFIG;
    }

    if (!rsa_keybits_is_valid((unsigned int)keybits)) {
        rsa_set_error(ctx, "invalid keybits (use 2048, 3072 or 4096)");
        return DVCO_CP_ERR_CONFIG;
    }

    ctx->pref_keybits = (unsigned int)keybits;
    return DVCO_CP_OK;
}

static int rsa_load_cfg(rsa_cipher_ctx_t *ctx, const dvco_kv_t *cfg, size_t cfg_count) {
    size_t i;

    if (ctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    for (i = 0u; i < cfg_count; i++) {
        if (cfg[i].key == NULL || cfg[i].value == NULL) {
            continue;
        }

        if (strcmp(cfg[i].key, "keybits") == 0) {
            if (rsa_apply_keybits_string(ctx, cfg[i].value) != DVCO_CP_OK) {
                return DVCO_CP_ERR_CONFIG;
            }
        } else {
            rsa_set_error(ctx, "unknown config key for rsa-oaep provider");
            return DVCO_CP_ERR_CONFIG;
        }
    }

    return DVCO_CP_OK;
}

static void rsa_replace_key(rsa_cipher_ctx_t *ctx, EVP_PKEY *pkey, int has_private) {
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

static int rsa_copy_bio_to_out(rsa_cipher_ctx_t *ctx, BIO *bio, dvco_buf_t *out) {
    BUF_MEM *bptr = NULL;
    size_t needed;

    if (ctx == NULL || bio == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    BIO_get_mem_ptr(bio, &bptr);
    if (bptr == NULL || bptr->data == NULL) {
        rsa_set_error(ctx, "BIO_get_mem_ptr failed");
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

static int rsa_setup_oaep_ctx(rsa_cipher_ctx_t *ctx, EVP_PKEY_CTX *pctx) {
    if (ctx == NULL || pctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        rsa_set_error(ctx, "EVP_PKEY_CTX_set_rsa_padding failed");
        return DVCO_CP_ERR_CRYPTO;
    }

    if (EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256()) <= 0) {
        rsa_set_error(ctx, "EVP_PKEY_CTX_set_rsa_oaep_md failed");
        return DVCO_CP_ERR_CRYPTO;
    }

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) <= 0) {
        rsa_set_error(ctx, "EVP_PKEY_CTX_set_rsa_mgf1_md failed");
        return DVCO_CP_ERR_CRYPTO;
    }

    return DVCO_CP_OK;
}

static int rsa_blob_compare(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len) {
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

// --------------------------------------------------------------------------
// Provider API implementation
// --------------------------------------------------------------------------

static int rsa_get_info(dvco_cipher_provider_info_t *out_info) {
    if (out_info == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    memset(out_info, 0, sizeof(*out_info));

    out_info->abi_major        = DVCO_CIPHER_PROVIDER_API_VERSION_MAJOR;
    out_info->abi_minor        = DVCO_CIPHER_PROVIDER_API_VERSION_MINOR;
    out_info->provider_name    = DVCO_RSA_PROVIDER_NAME;
    out_info->provider_version = DVCO_RSA_PROVIDER_VERSION;
    out_info->provider_desc    = DVCO_RSA_PROVIDER_DESC;
    out_info->cid              = DVCO_CIPHER_ID;
    out_info->pad_apply        = false;
    out_info->pad_block_size   = 1u;
    out_info->category_flags   = CRAG_PROVIDER_CATEGORY_ASYMMETRIC;

    return DVCO_CP_OK;
}

static int rsa_create(const dvco_kv_t *cfg, size_t cfg_count, dvco_cipher_ctx_t **out_ctx) {
    rsa_cipher_ctx_t *ctx;
    int rc;

    if (out_ctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_ctx = NULL;

    ctx = (rsa_cipher_ctx_t *)calloc(1u, sizeof(*ctx));
    if (ctx == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }

    ctx->pkey = NULL;
    ctx->pref_keybits = DVCO_RSA_KEYBITS_DEFAULT;
    ctx->has_public = 0;
    ctx->has_private = 0;
    rsa_set_error(ctx, NULL);

    rc = rsa_load_cfg(ctx, cfg, cfg_count);
    if (rc != DVCO_CP_OK) {
        rsa_secure_zero(ctx, sizeof(*ctx));
        free(ctx);
        return rc;
    }

    *out_ctx = (dvco_cipher_ctx_t *)ctx;
    return DVCO_CP_OK;
}

static void rsa_destroy(dvco_cipher_ctx_t *ctx) {
    rsa_cipher_ctx_t *r = rsa_ctx_from_opaque(ctx);

    if (r == NULL) {
        return;
    }

    if (r->pkey != NULL) {
        EVP_PKEY_free(r->pkey);
        r->pkey = NULL;
    }

    rsa_secure_zero(r, sizeof(*r));
    free(r);
}

static int rsa_reset(dvco_cipher_ctx_t *ctx) {
    rsa_cipher_ctx_t *r = rsa_ctx_from_opaque(ctx);

    if (r == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    rsa_set_error(r, NULL);
    return DVCO_CP_OK;
}

static int rsa_rotate(dvco_cipher_ctx_t *ctx) {
    rsa_cipher_ctx_t *r = rsa_ctx_from_opaque(ctx);
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    int rc = DVCO_CP_ERR_CRYPTO;

    if (r == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    rsa_set_error(r, NULL);

    if (!rsa_keybits_is_valid(r->pref_keybits)) {
        rsa_set_error(r, "invalid preferred RSA keybits");
        return DVCO_CP_ERR_BAD_STATE;
    }

    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (kctx == NULL) {
        rsa_set_error(r, "EVP_PKEY_CTX_new_id failed");
        return DVCO_CP_ERR_ALLOC;
    }

    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        rsa_set_error(r, "EVP_PKEY_keygen_init failed");
        goto done;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, (int)r->pref_keybits) <= 0) {
        rsa_set_error(r, "EVP_PKEY_CTX_set_rsa_keygen_bits failed");
        goto done;
    }

    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        rsa_set_error(r, "EVP_PKEY_keygen failed");
        goto done;
    }

    rsa_replace_key(r, pkey, 1);
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

static int rsa_serialize_shareable(dvco_cipher_ctx_t *ctx, dvco_buf_t *out) {
    rsa_cipher_ctx_t *r = rsa_ctx_from_opaque(ctx);
    BIO *bio = NULL;
    int rc;

    if (r == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (r->pkey == NULL || !r->has_public) {
        rsa_set_error(r, "provider has no public key; rotate or deserialize first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        rsa_set_error(r, "BIO_new failed");
        return DVCO_CP_ERR_ALLOC;
    }

    if (PEM_write_bio_PUBKEY(bio, r->pkey) != 1) {
        rsa_set_error(r, "PEM_write_bio_PUBKEY failed");
        BIO_free(bio);
        return DVCO_CP_ERR_CRYPTO;
    }

    rc = rsa_copy_bio_to_out(r, bio, out);
    BIO_free(bio);
    return rc;
}

static int rsa_deserialize_shareable(dvco_cipher_ctx_t *ctx, const uint8_t *in_data, size_t in_len) {
    rsa_cipher_ctx_t *r = rsa_ctx_from_opaque(ctx);
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;

    if (r == NULL || in_data == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (in_len == 0u) {
        rsa_set_error(r, "public key blob is empty");
        return DVCO_CP_ERR_PARSE;
    }

    bio = BIO_new_mem_buf((const void *)in_data, (int)in_len);
    if (bio == NULL) {
        rsa_set_error(r, "BIO_new_mem_buf failed");
        return DVCO_CP_ERR_ALLOC;
    }

    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (pkey == NULL) {
        rsa_set_error(r, "PEM_read_bio_PUBKEY failed");
        return DVCO_CP_ERR_PARSE;
    }

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        EVP_PKEY_free(pkey);
        rsa_set_error(r, "public key is not RSA");
        return DVCO_CP_ERR_PARSE;
    }

    rsa_replace_key(r, pkey, 0);
    return DVCO_CP_OK;
}

static int rsa_compare_shareable(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    rsa_cipher_ctx_t *r = rsa_ctx_from_opaque(ctx);
    dvco_buf_t tmp;
    uint8_t *buf = NULL;
    int rc;

    if (r == NULL || blob == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    memset(&tmp, 0, sizeof(tmp));
    rc = rsa_serialize_shareable(ctx, &tmp);
    if (rc != DVCO_CP_OK) {
        return rc;
    }

    buf = (uint8_t *)malloc(tmp.len);
    if (buf == NULL) {
        rsa_set_error(r, "temporary compare buffer allocation failed");
        return DVCO_CP_ERR_ALLOC;
    }

    tmp.data = buf;
    tmp.cap = tmp.len;
    rc = rsa_serialize_shareable(ctx, &tmp);
    if (rc == DVCO_CP_OK) {
        rc = rsa_blob_compare(tmp.data, tmp.len, blob, blob_len) ? DVCO_CP_OK : DVCO_CP_ERR_PARSE;
        if (rc != DVCO_CP_OK) {
            rsa_set_error(r, "shareable blob content mismatch");
        }
    }

    rsa_secure_zero(buf, tmp.cap);
    free(buf);
    return rc;
}

static int rsa_serialize_private(dvco_cipher_ctx_t *ctx, dvco_buf_t *out) {
    rsa_cipher_ctx_t *r = rsa_ctx_from_opaque(ctx);
    BIO *bio = NULL;
    int rc;

    if (r == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (r->pkey == NULL || !r->has_private) {
        rsa_set_error(r, "provider has no private key; rotate or deserialize_private first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        rsa_set_error(r, "BIO_new failed");
        return DVCO_CP_ERR_ALLOC;
    }

    if (PEM_write_bio_PrivateKey(bio, r->pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        rsa_set_error(r, "PEM_write_bio_PrivateKey failed");
        BIO_free(bio);
        return DVCO_CP_ERR_CRYPTO;
    }

    rc = rsa_copy_bio_to_out(r, bio, out);
    BIO_free(bio);
    return rc;
}

static int rsa_deserialize_private(dvco_cipher_ctx_t *ctx, const uint8_t *in_data, size_t in_len) {
    rsa_cipher_ctx_t *r = rsa_ctx_from_opaque(ctx);
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;

    if (r == NULL || in_data == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (in_len == 0u) {
        rsa_set_error(r, "private key blob is empty");
        return DVCO_CP_ERR_PARSE;
    }

    bio = BIO_new_mem_buf((const void *)in_data, (int)in_len);
    if (bio == NULL) {
        rsa_set_error(r, "BIO_new_mem_buf failed");
        return DVCO_CP_ERR_ALLOC;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (pkey == NULL) {
        rsa_set_error(r, "PEM_read_bio_PrivateKey failed");
        return DVCO_CP_ERR_PARSE;
    }

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
        EVP_PKEY_free(pkey);
        rsa_set_error(r, "private key is not RSA");
        return DVCO_CP_ERR_PARSE;
    }

    rsa_replace_key(r, pkey, 1);
    return DVCO_CP_OK;
}

static int rsa_compare_private(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    rsa_cipher_ctx_t *r = rsa_ctx_from_opaque(ctx);
    dvco_buf_t tmp;
    uint8_t *buf = NULL;
    int rc;

    if (r == NULL || blob == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    memset(&tmp, 0, sizeof(tmp));
    rc = rsa_serialize_private(ctx, &tmp);
    if (rc != DVCO_CP_OK) {
        return rc;
    }

    buf = (uint8_t *)malloc(tmp.len);
    if (buf == NULL) {
        rsa_set_error(r, "temporary compare buffer allocation failed");
        return DVCO_CP_ERR_ALLOC;
    }

    tmp.data = buf;
    tmp.cap = tmp.len;
    rc = rsa_serialize_private(ctx, &tmp);
    if (rc == DVCO_CP_OK) {
        rc = rsa_blob_compare(tmp.data, tmp.len, blob, blob_len) ? DVCO_CP_OK : DVCO_CP_ERR_PARSE;
        if (rc != DVCO_CP_OK) {
            rsa_set_error(r, "private blob content mismatch");
        }
    }

    rsa_secure_zero(buf, tmp.cap);
    free(buf);
    return rc;
}

static int rsa_encrypt(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out
) {
    rsa_cipher_ctx_t *r = rsa_ctx_from_opaque(ctx);
    EVP_PKEY_CTX *pctx = NULL;
    size_t needed = 0u;
    int rc = DVCO_CP_ERR_CRYPTO;

    if (r == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (r->pkey == NULL || !r->has_public) {
        rsa_set_error(r, "provider has no public key; rotate or deserialize_shareable first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if ((in_len > 0u) && (in_data == NULL)) {
        rsa_set_error(r, "encrypt input is NULL");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (aad != NULL || aad_len != 0u) {
        rsa_set_error(r, "AAD not supported by RSA-OAEP provider");
        return DVCO_CP_ERR_NOT_SUPPORTED;
    }

    pctx = EVP_PKEY_CTX_new(r->pkey, NULL);
    if (pctx == NULL) {
        rsa_set_error(r, "EVP_PKEY_CTX_new failed");
        return DVCO_CP_ERR_ALLOC;
    }

    if (EVP_PKEY_encrypt_init(pctx) <= 0) {
        rsa_set_error(r, "EVP_PKEY_encrypt_init failed");
        goto done;
    }

    rc = rsa_setup_oaep_ctx(r, pctx);
    if (rc != DVCO_CP_OK) {
        goto done;
    }

    if (EVP_PKEY_encrypt(pctx, NULL, &needed, in_data, in_len) <= 0) {
        rsa_set_error(r, "EVP_PKEY_encrypt sizing failed");
        rc = DVCO_CP_ERR_CRYPTO;
        goto done;
    }

    if (out->data == NULL) {
        out->len = needed;
        rc = DVCO_CP_OK;
        goto done;
    }

    if (out->cap < needed) {
        out->len = needed;
        rc = DVCO_CP_ERR_BUFFER_TOO_SMALL;
        goto done;
    }

    if (EVP_PKEY_encrypt(pctx, out->data, &needed, in_data, in_len) <= 0) {
        rsa_set_error(r, "EVP_PKEY_encrypt failed");
        rc = DVCO_CP_ERR_CRYPTO;
        goto done;
    }

    out->len = needed;
    rc = DVCO_CP_OK;

done:
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
    return rc;
}

static int rsa_decrypt(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out
) {
    rsa_cipher_ctx_t *r = rsa_ctx_from_opaque(ctx);
    EVP_PKEY_CTX *pctx = NULL;
    size_t needed = 0u;
    int rc = DVCO_CP_ERR_CRYPTO;

    if (r == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (r->pkey == NULL || !r->has_private) {
        rsa_set_error(r, "provider has no private key; rotate or deserialize_private first");
        return DVCO_CP_ERR_BAD_STATE;
    }

    if (in_data == NULL) {
        rsa_set_error(r, "decrypt input is NULL");
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (aad != NULL || aad_len != 0u) {
        rsa_set_error(r, "AAD not supported by RSA-OAEP provider");
        return DVCO_CP_ERR_NOT_SUPPORTED;
    }

    pctx = EVP_PKEY_CTX_new(r->pkey, NULL);
    if (pctx == NULL) {
        rsa_set_error(r, "EVP_PKEY_CTX_new failed");
        return DVCO_CP_ERR_ALLOC;
    }

    if (EVP_PKEY_decrypt_init(pctx) <= 0) {
        rsa_set_error(r, "EVP_PKEY_decrypt_init failed");
        goto done;
    }

    rc = rsa_setup_oaep_ctx(r, pctx);
    if (rc != DVCO_CP_OK) {
        goto done;
    }

    if (EVP_PKEY_decrypt(pctx, NULL, &needed, in_data, in_len) <= 0) {
        rsa_set_error(r, "EVP_PKEY_decrypt sizing failed");
        rc = DVCO_CP_ERR_CRYPTO;
        goto done;
    }

    if (out->data == NULL) {
        out->len = needed;
        rc = DVCO_CP_OK;
        goto done;
    }

    if (out->cap < needed) {
        out->len = needed;
        rc = DVCO_CP_ERR_BUFFER_TOO_SMALL;
        goto done;
    }

    if (EVP_PKEY_decrypt(pctx, out->data, &needed, in_data, in_len) <= 0) {
        rsa_set_error(r, "EVP_PKEY_decrypt failed");
        rc = DVCO_CP_ERR_CRYPTO;
        goto done;
    }

    out->len = needed;
    rc = DVCO_CP_OK;

done:
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
    return rc;
}

static const char *rsa_last_error(dvco_cipher_ctx_t *ctx) {
    rsa_cipher_ctx_t *r = rsa_ctx_from_opaque(ctx);

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

static const dvco_cipher_provider_api_t g_rsa_provider_api = {
    .get_info              = rsa_get_info,
    .create                = rsa_create,
    .destroy               = rsa_destroy,
    .reset                 = rsa_reset,
    .rotate                = rsa_rotate,
    .serialize_shareable   = rsa_serialize_shareable,
    .deserialize_shareable = rsa_deserialize_shareable,
    .compare_shareable     = rsa_compare_shareable,
    .serialize_private     = rsa_serialize_private,
    .deserialize_private   = rsa_deserialize_private,
    .compare_private       = rsa_compare_private,
    .encrypt               = rsa_encrypt,
    .decrypt               = rsa_decrypt,
    .last_error            = rsa_last_error
};

// --------------------------------------------------------------------------
// Plugin entry point
// --------------------------------------------------------------------------

int dvco_cipher_provider_get_api(const dvco_cipher_provider_api_t **out_api) {
    if (out_api == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_api = &g_rsa_provider_api;
    return DVCO_CP_OK;
}

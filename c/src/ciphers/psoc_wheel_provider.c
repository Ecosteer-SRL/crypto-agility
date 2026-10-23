// SPDX-FileCopyrightText: 2026 Ecosteer srl
// SPDX-License-Identifier: MIT
// ver: 2.0 2026-10-23

//  ver: 2.0
//  capability_flag added

//  !!!! WARNING !!!!
//  !!!! WARNING !!!!
//  !!!! WARNING !!!!
//  !!!! WARNING !!!!
// Deterministic architecture-validation provider.
// This provider deliberately provides no cryptographic security (just obvious encoding).
//  DO NOT USE THIS CIPHER

#include "ciphers/cipher_provider.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PSOC_WHEEL_CID                 ((dvco_selector_t)200u)
#define PSOC_WHEEL_BLOCK_SIZE          8u
#define PSOC_WHEEL_KEY_SIZE            8u
#define PSOC_WHEEL_GENERATION_COUNT    8u

typedef enum psoc_wheel_error_e {
    PSOC_WHEEL_ERROR_NONE = 0,
    PSOC_WHEEL_ERROR_INACTIVE,
    PSOC_WHEEL_ERROR_NULL_INPUT,
    PSOC_WHEEL_ERROR_AAD_UNSUPPORTED,
    PSOC_WHEEL_ERROR_ENCRYPT_LENGTH,
    PSOC_WHEEL_ERROR_DECRYPT_LENGTH,
    PSOC_WHEEL_ERROR_SERIALIZED_LENGTH,
    PSOC_WHEEL_ERROR_SERIALIZED_MISMATCH,
    PSOC_WHEEL_ERROR_OUTPUT_TOO_SMALL
} psoc_wheel_error_t;

typedef struct psoc_wheel_ctx_s {
    uint8_t key[PSOC_WHEEL_KEY_SIZE];
    uint8_t active;
    uint8_t last_error;
} psoc_wheel_ctx_t;

static uint8_t g_psoc_wheel_next_generation;

static psoc_wheel_ctx_t *psoc_wheel_ctx_from_opaque(dvco_cipher_ctx_t *ctx) {
    return (psoc_wheel_ctx_t *)ctx;
}

static void psoc_wheel_secure_zero(void *data, size_t len) {
    volatile uint8_t *bytes = (volatile uint8_t *)data;

    while (len > 0u) {
        *bytes = 0u;
        bytes++;
        len--;
    }
}

static void psoc_wheel_set_error(
    psoc_wheel_ctx_t *ctx,
    psoc_wheel_error_t error
) {
    if (ctx != NULL) {
        ctx->last_error = (uint8_t)error;
    }
}

static uint8_t psoc_wheel_rol8(uint8_t value, uint8_t shift) {
    uint16_t wide_value;

    shift &= 0x07u;
    if (shift == 0u) {
        return value;
    }

    wide_value = (uint16_t)value;
    return (uint8_t)(
        (uint16_t)(wide_value << shift) |
        (uint16_t)(wide_value >> (8u - shift))
    );
}

static uint8_t psoc_wheel_ror8(uint8_t value, uint8_t shift) {
    uint16_t wide_value;

    shift &= 0x07u;
    if (shift == 0u) {
        return value;
    }

    wide_value = (uint16_t)value;
    return (uint8_t)(
        (uint16_t)(wide_value >> shift) |
        (uint16_t)(wide_value << (8u - shift))
    );
}

static int psoc_wheel_get_info(dvco_cipher_provider_info_t *out_info) {
    if (out_info == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    memset(out_info, 0, sizeof(*out_info));
    out_info->abi_major = DVCO_CIPHER_PROVIDER_API_VERSION_MAJOR;
    out_info->abi_minor = DVCO_CIPHER_PROVIDER_API_VERSION_MINOR;
    out_info->provider_name = "psoc-wheel";
    out_info->provider_version = "1.0.0";
    out_info->provider_desc =
        "Deterministic non-cryptographic architecture-validation provider";
    out_info->cid = PSOC_WHEEL_CID;
    out_info->pad_apply = true;
    out_info->pad_block_size = PSOC_WHEEL_BLOCK_SIZE;
    out_info->category_flags = CRAG_PROVIDER_CATEGORY_SYMMETRIC;
    out_info->capability_flags  = CRAG_CAP_EXTERNAL_INTEGRITY_CHECK;

    return DVCO_CP_OK;
}

static int psoc_wheel_create(
    const dvco_kv_t *cfg,
    size_t cfg_count,
    dvco_cipher_ctx_t **out_ctx
) {
    psoc_wheel_ctx_t *ctx;

    (void)cfg;
    if (out_ctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_ctx = NULL;
    if (cfg_count != 0u) {
        return DVCO_CP_ERR_CONFIG;
    }

    ctx = (psoc_wheel_ctx_t *)calloc(1u, sizeof(*ctx));
    if (ctx == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }

    *out_ctx = (dvco_cipher_ctx_t *)ctx;
    return DVCO_CP_OK;
}

static void psoc_wheel_destroy(dvco_cipher_ctx_t *ctx) {
    psoc_wheel_ctx_t *wheel_ctx = psoc_wheel_ctx_from_opaque(ctx);

    if (wheel_ctx == NULL) {
        return;
    }

    psoc_wheel_secure_zero(wheel_ctx, sizeof(*wheel_ctx));
    free(wheel_ctx);
}

static int psoc_wheel_reset(dvco_cipher_ctx_t *ctx) {
    psoc_wheel_ctx_t *wheel_ctx = psoc_wheel_ctx_from_opaque(ctx);

    if (wheel_ctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    // There is no transient operation state. Keep the active key.
    psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_NONE);
    return DVCO_CP_OK;
}

static int psoc_wheel_rotate(dvco_cipher_ctx_t *ctx) {
    psoc_wheel_ctx_t *wheel_ctx = psoc_wheel_ctx_from_opaque(ctx);
    uint8_t generation;
    size_t index;

    if (wheel_ctx == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    generation = (uint8_t)(
        g_psoc_wheel_next_generation % PSOC_WHEEL_GENERATION_COUNT
    );
    for (index = 0u; index < PSOC_WHEEL_KEY_SIZE; index++) {
        wheel_ctx->key[index] = (uint8_t)(
            (generation + (uint8_t)index) % PSOC_WHEEL_GENERATION_COUNT
        );
    }

    wheel_ctx->active = 1u;
    g_psoc_wheel_next_generation = (uint8_t)(
        (generation + 1u) % PSOC_WHEEL_GENERATION_COUNT
    );
    psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_NONE);
    return DVCO_CP_OK;
}

static int psoc_wheel_serialize_key(
    dvco_cipher_ctx_t *ctx,
    dvco_buf_t *out
) {
    psoc_wheel_ctx_t *wheel_ctx = psoc_wheel_ctx_from_opaque(ctx);

    if (wheel_ctx == NULL || out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }
    if (wheel_ctx->active == 0u) {
        psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_INACTIVE);
        return DVCO_CP_ERR_BAD_STATE;
    }
    if (out->data == NULL) {
        out->len = PSOC_WHEEL_KEY_SIZE;
        psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_NONE);
        return DVCO_CP_OK;
    }
    if (out->cap < PSOC_WHEEL_KEY_SIZE) {
        out->len = PSOC_WHEEL_KEY_SIZE;
        psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_OUTPUT_TOO_SMALL);
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(out->data, wheel_ctx->key, PSOC_WHEEL_KEY_SIZE);
    out->len = PSOC_WHEEL_KEY_SIZE;
    psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_NONE);
    return DVCO_CP_OK;
}

static int psoc_wheel_deserialize_key(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len
) {
    psoc_wheel_ctx_t *wheel_ctx = psoc_wheel_ctx_from_opaque(ctx);

    if (wheel_ctx == NULL || in_data == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }
    if (in_len != PSOC_WHEEL_KEY_SIZE) {
        psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_SERIALIZED_LENGTH);
        return DVCO_CP_ERR_PARSE;
    }

    memcpy(wheel_ctx->key, in_data, PSOC_WHEEL_KEY_SIZE);
    wheel_ctx->active = 1u;
    psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_NONE);
    return DVCO_CP_OK;
}

static int psoc_wheel_compare_key(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    psoc_wheel_ctx_t *wheel_ctx = psoc_wheel_ctx_from_opaque(ctx);
    uint8_t difference = 0u;
    size_t index;

    if (wheel_ctx == NULL || blob == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }
    if (wheel_ctx->active == 0u) {
        psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_INACTIVE);
        return DVCO_CP_ERR_BAD_STATE;
    }
    if (blob_len != PSOC_WHEEL_KEY_SIZE) {
        psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_SERIALIZED_LENGTH);
        return DVCO_CP_ERR_PARSE;
    }

    for (index = 0u; index < PSOC_WHEEL_KEY_SIZE; index++) {
        difference |= (uint8_t)(wheel_ctx->key[index] ^ blob[index]);
    }
    if (difference != 0u) {
        psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_SERIALIZED_MISMATCH);
        return DVCO_CP_ERR_PARSE;
    }

    psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_NONE);
    return DVCO_CP_OK;
}

static int psoc_wheel_serialize_shareable(
    dvco_cipher_ctx_t *ctx,
    dvco_buf_t *out
) {
    return psoc_wheel_serialize_key(ctx, out);
}

static int psoc_wheel_deserialize_shareable(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len
) {
    return psoc_wheel_deserialize_key(ctx, in_data, in_len);
}

static int psoc_wheel_compare_shareable(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    return psoc_wheel_compare_key(ctx, blob, blob_len);
}

static int psoc_wheel_serialize_private(
    dvco_cipher_ctx_t *ctx,
    dvco_buf_t *out
) {
    return psoc_wheel_serialize_key(ctx, out);
}

static int psoc_wheel_deserialize_private(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len
) {
    return psoc_wheel_deserialize_key(ctx, in_data, in_len);
}

static int psoc_wheel_compare_private(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *blob,
    size_t blob_len
) {
    return psoc_wheel_compare_key(ctx, blob, blob_len);
}

static int psoc_wheel_validate_operation(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out,
    psoc_wheel_ctx_t **wheel_ctx_out,
    int length_error,
    psoc_wheel_error_t length_diagnostic
) {
    psoc_wheel_ctx_t *wheel_ctx = psoc_wheel_ctx_from_opaque(ctx);

    if (wheel_ctx == NULL || out == NULL || wheel_ctx_out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }
    if (wheel_ctx->active == 0u) {
        psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_INACTIVE);
        return DVCO_CP_ERR_BAD_STATE;
    }
    if (in_data == NULL) {
        psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_NULL_INPUT);
        return DVCO_CP_ERR_INVALID_ARG;
    }

    // Match the current non-AAD Linux providers and the PSoC implementation.
    if (aad != NULL || aad_len != 0u) {
        psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_AAD_UNSUPPORTED);
        return DVCO_CP_ERR_NOT_SUPPORTED;
    }
    if (in_len == 0u || (in_len % PSOC_WHEEL_BLOCK_SIZE) != 0u) {
        psoc_wheel_set_error(wheel_ctx, length_diagnostic);
        return length_error;
    }
    if (out->data == NULL) {
        out->len = in_len;
        psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_NONE);
        return DVCO_CP_OK;
    }
    if (out->cap < in_len) {
        out->len = in_len;
        psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_OUTPUT_TOO_SMALL);
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    *wheel_ctx_out = wheel_ctx;
    return DVCO_CP_OK;
}

static int psoc_wheel_encrypt(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out
) {
    psoc_wheel_ctx_t *wheel_ctx = NULL;
    size_t offset;
    size_t index;
    int rc;

    rc = psoc_wheel_validate_operation(
        ctx, in_data, in_len, aad, aad_len, out, &wheel_ctx,
        DVCO_CP_ERR_INVALID_ARG, PSOC_WHEEL_ERROR_ENCRYPT_LENGTH
    );
    if (rc != DVCO_CP_OK || out->data == NULL) {
        return rc;
    }

    for (offset = 0u; offset < in_len; offset += PSOC_WHEEL_BLOCK_SIZE) {
        for (index = 0u; index < PSOC_WHEEL_BLOCK_SIZE; index++) {
            out->data[offset + index] = psoc_wheel_rol8(
                in_data[offset + index],
                (uint8_t)(wheel_ctx->key[index] & 0x07u)
            );
        }
    }

    out->len = in_len;
    psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_NONE);
    return DVCO_CP_OK;
}

static int psoc_wheel_decrypt(
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    const uint8_t *aad,
    size_t aad_len,
    dvco_buf_t *out
) {
    psoc_wheel_ctx_t *wheel_ctx = NULL;
    size_t offset;
    size_t index;
    int rc;

    rc = psoc_wheel_validate_operation(
        ctx, in_data, in_len, aad, aad_len, out, &wheel_ctx,
        DVCO_CP_ERR_PARSE, PSOC_WHEEL_ERROR_DECRYPT_LENGTH
    );
    if (rc != DVCO_CP_OK || out->data == NULL) {
        return rc;
    }

    for (offset = 0u; offset < in_len; offset += PSOC_WHEEL_BLOCK_SIZE) {
        for (index = 0u; index < PSOC_WHEEL_BLOCK_SIZE; index++) {
            out->data[offset + index] = psoc_wheel_ror8(
                in_data[offset + index],
                (uint8_t)(wheel_ctx->key[index] & 0x07u)
            );
        }
    }

    out->len = in_len;
    psoc_wheel_set_error(wheel_ctx, PSOC_WHEEL_ERROR_NONE);
    return DVCO_CP_OK;
}

static const char *psoc_wheel_last_error(dvco_cipher_ctx_t *ctx) {
    psoc_wheel_ctx_t *wheel_ctx = psoc_wheel_ctx_from_opaque(ctx);

    if (wheel_ctx == NULL) {
        return "invalid psoc-wheel provider context";
    }

    switch ((psoc_wheel_error_t)wheel_ctx->last_error) {
        case PSOC_WHEEL_ERROR_NONE:
            return NULL;
        case PSOC_WHEEL_ERROR_INACTIVE:
            return "provider is not active; rotate or deserialize first";
        case PSOC_WHEEL_ERROR_NULL_INPUT:
            return "input is NULL";
        case PSOC_WHEEL_ERROR_AAD_UNSUPPORTED:
            return "AAD is not supported by psoc-wheel";
        case PSOC_WHEEL_ERROR_ENCRYPT_LENGTH:
            return "plaintext length must be a non-zero multiple of 8";
        case PSOC_WHEEL_ERROR_DECRYPT_LENGTH:
            return "ciphertext length must be a non-zero multiple of 8";
        case PSOC_WHEEL_ERROR_SERIALIZED_LENGTH:
            return "serialized key must be exactly 8 bytes";
        case PSOC_WHEEL_ERROR_SERIALIZED_MISMATCH:
            return "serialized key does not match";
        case PSOC_WHEEL_ERROR_OUTPUT_TOO_SMALL:
            return "output buffer is too small";
        default:
            return "unknown psoc-wheel provider error";
    }
}

static const dvco_cipher_provider_api_t g_psoc_wheel_provider_api = {
    .get_info = psoc_wheel_get_info,
    .create = psoc_wheel_create,
    .destroy = psoc_wheel_destroy,
    .reset = psoc_wheel_reset,
    .rotate = psoc_wheel_rotate,
    .serialize_shareable = psoc_wheel_serialize_shareable,
    .deserialize_shareable = psoc_wheel_deserialize_shareable,
    .compare_shareable = psoc_wheel_compare_shareable,
    .serialize_private = psoc_wheel_serialize_private,
    .deserialize_private = psoc_wheel_deserialize_private,
    .compare_private = psoc_wheel_compare_private,
    .encrypt = psoc_wheel_encrypt,
    .decrypt = psoc_wheel_decrypt,
    .last_error = psoc_wheel_last_error
};

int dvco_cipher_provider_get_api(
    const dvco_cipher_provider_api_t **out_api
) {
    if (out_api == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_api = &g_psoc_wheel_provider_api;
    return DVCO_CP_OK;
}

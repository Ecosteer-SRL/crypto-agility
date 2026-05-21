
// SPDX-FileCopyrightText: 2026 Daniel Grazioli (graz)
// SPDX-FileCopyrightText: 2026 Ecosteer srl
// SPDX-License-Identifier: MIT
// ver: 1.1

//  ver: 1.1
//  The field category_flag has been added to struct dvco_cipher_provider_info_s
//  category_flags defines how the upper layer must interpret shareable/private material.
//  A provider should set exactly one of SYMMETRIC or ASYMMETRIC for now.

#ifndef DVCO_CIPHER_PROVIDER_H
#define DVCO_CIPHER_PROVIDER_H

/*
 * DVCO VER 2 - Cipher Provider Common API (v1)
 *
 * Purpose
 * -------
 * Runtime-loadable cipher plugins (.so / shared libraries) used by DVCO publishers/subscribers.
 *
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif


/* =========================
 * ABI / API VERSIONING
 * ========================= */

#define DVCO_CIPHER_PROVIDER_API_VERSION_MAJOR 1u
#define DVCO_CIPHER_PROVIDER_API_VERSION_MINOR 1u

/* =========================
 * CATEGORY FLAGS
 * ========================= */
/*
    category_flags defines how the upper layer must interpret
    shareable/private provider material.
    
    For now, a provider SHOULD set exactly one of:
 
    CRAG_PROVIDER_CATEGORY_SYMMETRIC
    CRAG_PROVIDER_CATEGORY_ASYMMETRIC
 
    SYMMETRIC:
    serialize_shareable() and serialize_private() return material related
    to symmetric operational state. Both blobs may contain secret material
    and must be treated as sensitive unless the provider documents otherwise.
 
    ASYMMETRIC:
    serialize_shareable() returns public material.
    serialize_private() returns private material.
 */
#define CRAG_PROVIDER_CATEGORY_MASK         0x00FFu
#define CRAG_PROVIDER_CATEGORY_VARIANT_MASK 0xFF00u

#define CRAG_PROVIDER_CATEGORY_UNSPECIFIED  0x0000u
#define CRAG_PROVIDER_CATEGORY_SYMMETRIC    0x0001u
#define CRAG_PROVIDER_CATEGORY_ASYMMETRIC   0x0002u

/* =========================
 * COMMON TYPES
 * ========================= */

/* Marketplace / Domain selectors are 2-byte unsigned values */
typedef uint16_t dvco_selector_t;

/* Return codes (generic/common range) */
typedef enum dvco_cp_rc_e {
    DVCO_CP_OK = 0,

    DVCO_CP_ERR_GENERIC            = 1,
    DVCO_CP_ERR_INVALID_ARG        = 2,
    DVCO_CP_ERR_BAD_STATE          = 3,
    DVCO_CP_ERR_NOT_SUPPORTED      = 4,
    DVCO_CP_ERR_ALLOC              = 5,
    DVCO_CP_ERR_BUFFER_TOO_SMALL   = 6,
    DVCO_CP_ERR_PARSE              = 7,
    DVCO_CP_ERR_CONFIG             = 8,
    DVCO_CP_ERR_CRYPTO             = 9
} dvco_cp_rc_t;

/* Opaque provider instance handle */
typedef struct dvco_cipher_ctx_s dvco_cipher_ctx_t;

/*
 * Buffer helper used by API methods.
 * - data may be NULL when querying required size.
 * - len is in/out depending on method.
 */
typedef struct dvco_buf_s {
    uint8_t *data;      
    size_t   len;   //  len of data content
    size_t   cap;   //  capacity of data buffer (len might be less than cap)
} dvco_buf_t;

/*
 * Optional key/value config item (for static marketplace config-driven provider instantiation).
 * Example use:
 *   "mode" = "CBC"
 *   "keybits" = "256"
 *   "impl" = "openssl"
 *
 * Interpretation is provider-specific.
 */
typedef struct dvco_kv_s {
    const char *key;
    const char *value;
} dvco_kv_t;

/* =========================
 * PROVIDER METADATA
 * ========================= */

typedef struct dvco_cipher_provider_info_s {
    uint32_t abi_major;       /* must match DVCO_CIPHER_PROVIDER_API_VERSION_MAJOR */
    uint32_t abi_minor;       /* compatible minor version */

    const char *provider_name;      /* e.g. "aes" */
    const char *provider_version;   /* provider impl version string */
    const char *provider_desc;      /* free text */

    /* Selector values assigned by marketplace config / domain mapping */
    //dvco_selector_t iid; /* Integrity selector (currently CRC16 fixed in runtime, but carried in representation) */
    dvco_selector_t cid; /* Cipher selector */

    bool   pad_apply;               //  if true then the upper layer will have to apply pkcs7 padding
    size_t pad_block_size;          //  in case the upper layer must apply padding - it will have to use this block size

    uint16_t category_flags;        //  tells the upper layer how to treat shareable/private material

} dvco_cipher_provider_info_t;

/* =========================
 * OPERATION CONTRACT
 * ========================= */

/*
 * Shareable Representation (transported in DVCO "key" field)
 * ----------------------------------------------------------
 * The semantic meaning of shareable material depends on provider category.
 *
 * For SYMMETRIC providers:
 *   serialize_shareable() normally returns material required by another
 *   context to reconstruct equivalent operational encrypt/decrypt state.
 *
 * For ASYMMETRIC providers:
 *   serialize_shareable() normally returns public material only.
 *   Private/decrypt-capable material belongs to serialize_private().
 *
 * The returned bytes are provider-defined and opaque to the caller.
 *
 * The caller/wire protocol is responsible for prepending/selecting IID/CID
 * if needed by protocol framing.
 */

 
/* =========================
 * PROVIDER VTABLE
 * ========================= */

typedef struct dvco_cipher_provider_api_s {

    /* ---- Metadata ---- */

    int (*get_info)(dvco_cipher_provider_info_t *out_info);

    /* ---- Lifecycle ---- */

    /*
     * Create a provider instance.
     * cfg/cfg_count comes from static marketplace config (provider-specific).
     */
    int (*create)(
        const dvco_kv_t       *cfg,
        size_t                 cfg_count,
        dvco_cipher_ctx_t    **out_ctx
    );

    /*
     * Destroy provider instance and wipe sensitive internal state if applicable.
     */
    void (*destroy)(
        dvco_cipher_ctx_t *ctx
    );

    /*
     * Reset/rotate internal runtime state (optional).
     * Can be used when publisher rotates stream crypto context.
     */
    int (*reset)(
        dvco_cipher_ctx_t *ctx
    );


    /*
     * Rotate provider state for the active stream.
     *
     * This method MUST generate and activate a fresh cryptographic state
     * (for example: a new symmetric key and/or other provider-specific state)
     * suitable for subsequent encrypt() operations.
     *
     * After a successful rotate():
     *   - the provider instance SHALL be in an active/usable state
     *   - serialize_shareable() SHALL export the newly generated shareable state
     *   - serialize_private() (if supported) SHALL export the corresponding local state
     *
     * params/params_count are optional provider-specific rotation parameters.
     * Typical examples:
     *   "keybits" = "256"
     *   "reseed"  = "1"
     *
     * A provider MAY ignore unsupported params and return DVCO_CP_ERR_CONFIG
     * for invalid values.
     *
     * Providers that require rotation before first use SHOULD make encrypt()
     * fail with DVCO_CP_ERR_BAD_STATE until rotate() or deserialize_shareable()
     * has been called successfully.
     */

    int (*rotate)(
        dvco_cipher_ctx_t   *ctx
    );

    /* ---- Shareable / Private state serialization ---- */

    /*
     * Serialize provider "shareable" opaque bytes.
     * Used for DVCO_PUB_KEYSET and DVCO_SUB_KEYGET ("key" semantic extension).
     *
     * Two-call pattern supported:
     *   1) out->data = NULL; out->len = 0; function returns DVCO_CP_OK and sets required out->len
     *   2) caller allocates out->data with that size and calls again
     */
    int (*serialize_shareable)(
        dvco_cipher_ctx_t *ctx,
        dvco_buf_t        *out
    );

    /*
     * Restore provider state from "shareable" opaque bytes received from sender / proxy / OOB-kid lookup.
     */
    int (*deserialize_shareable)(
        dvco_cipher_ctx_t   *ctx,
        const uint8_t       *in_data,
        size_t               in_len
    );

    int (*compare_shareable)(
        dvco_cipher_ctx_t   *ctx,
        const uint8_t       *blob,
        size_t               blob_len
    );

    /*
     * Serialize provider "private" opaque bytes (local persistence / recovery).
     * Not transported in DVCO protocol unless explicitly decided by implementation.
     *
     * Optional in v1: may return DVCO_CP_ERR_NOT_SUPPORTED.
     */
    int (*serialize_private)(
        dvco_cipher_ctx_t *ctx,
        dvco_buf_t        *out
    );

    /*
     * Restore provider state from "private" opaque bytes.
     * Optional in v1.
     */
    int (*deserialize_private)(
        dvco_cipher_ctx_t   *ctx,
        const uint8_t       *in_data,
        size_t               in_len
    );

    int (*compare_private)(
        dvco_cipher_ctx_t   *ctx,
        const uint8_t       *blob,
        size_t               blob_len
    );

    /* ---- Crypto operations (symmetric payload path, v1) ---- */

    /*
     * Encrypt payload bytes.
     *
     * in_data / in_len:
     *   plaintext payload
     *
     * out:
     *   provider-defined ciphertext bytes ("cipher opaque data")
     *
     * aad / aad_len:
     *   optional associated data (may be NULL/0 in v1)
     *   reserved for future AEAD-capable providers
     *
     * Two-call output sizing pattern supported (same as serialize_*).
     */
    int (*encrypt)(
        dvco_cipher_ctx_t   *ctx,
        const uint8_t       *in_data,
        size_t               in_len,
        const uint8_t       *aad,           //  associated authenticated data
        size_t               aad_len,       //  associated authenticated data len
        dvco_buf_t          *out            //  holds data, len, cap
    );

    /*
     * Decrypt payload bytes.
     *
     * in_data / in_len:
     *   provider-defined ciphertext bytes ("cipher opaque data")
     *
     * out:
     *   plaintext payload
     *
     * aad / aad_len:
     *   optional associated data (must match encrypt if used)
     */
    int (*decrypt)(
        dvco_cipher_ctx_t   *ctx,
        const uint8_t       *in_data,
        size_t               in_len,
        const uint8_t       *aad,
        size_t               aad_len,
        dvco_buf_t          *out
    );

    /* ---- Diagnostics ---- */

    /*
     * Return last provider-specific error string (thread-safety is provider-defined).
     * Optional: may return NULL.
     */
    const char *(*last_error)(
        dvco_cipher_ctx_t *ctx
    );

} dvco_cipher_provider_api_t;



/* =========================
 * PLUGIN ENTRY POINT
 * ========================= */

/*
 * Each shared library plugin MUST export this symbol:
 *
 *   int dvco_cipher_provider_get_api(const dvco_cipher_provider_api_t **out_api);
 *
 * Return:
 *   DVCO_CP_OK on success
 *   error code otherwise
 */
typedef int (*dvco_cipher_provider_get_api_fn)(
    const dvco_cipher_provider_api_t **out_api
);

/* Canonical exported symbol name */
#define DVCO_CIPHER_PROVIDER_GET_API_SYMBOL "dvco_cipher_provider_get_api"

/* =========================
 * OPTIONAL HELPER UTILITIES
 * ========================= */

/*
 * Helper to build a shareable "key field" payload in the recommended v1 format:
 *   [IID:2][CID:2][opaque:N]
 *
 * Network byte order (big-endian) is RECOMMENDED for selectors.
 *
 * This function is declared here for consistency but can be implemented by the DVCO core
 * (not by plugins). If you don't want it here, move it to a core utility header.
 */
int dvco_cp_build_keyfield_payload(
    dvco_selector_t   cid,
    const uint8_t    *opaque,
    size_t            opaque_len,
    dvco_buf_t       *out
);

/*
 * Helper to parse the recommended v1 "key field" payload:
 *   [IID:2][CID:2][opaque:N]
 *
 * out_opaque points inside input buffer (no allocation).
 */
int dvco_cp_parse_keyfield_payload(
    const uint8_t    *in_data,
    size_t            in_len,
    dvco_selector_t  *out_cid,
    const uint8_t   **out_opaque,
    size_t           *out_opaque_len
);

#ifdef __cplusplus
}
#endif

#endif /* DVCO_CIPHER_PROVIDER_H */
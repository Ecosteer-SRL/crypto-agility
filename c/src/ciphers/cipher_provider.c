// SPDX-FileCopyrightText: 2026 Daniel Grazioli (graz)
// SPDX-FileCopyrightText: 2026 Ecosteer srl
// SPDX-License-Identifier: MIT
// ver: 1.0


#include "ciphers/cipher_provider.h"

#include <string.h>

/* -----------------------------
 * Internal endian helpers
 * ----------------------------- */

static void dvco_cp_u16_to_be(uint16_t v, uint8_t out[2]) {
    out[0] = (uint8_t)((v >> 8) & 0xFFu);
    out[1] = (uint8_t)(v & 0xFFu);
}

static uint16_t dvco_cp_u16_from_be(const uint8_t in[2]) {
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

/* -----------------------------
 * Public helpers
 * ----------------------------- */

 /*
 * dvco_cp_build_keyfield_payload
 * ------------------------------
 * Builds a binary keyfield payload with the following layout:
 *
 *   [CID:2][opaque:N]
 *
 * where:
 *   - CID is the cipher selector encoded in big-endian order
 *   - opaque is an optional provider-specific binary blob
 *
 * Purpose
 * -------
 * This helper is used at stack level to prepend the cipher selector (cid) to
 * a provider-generated opaque payload. The function is intentionally agnostic
 * with respect to the content of the opaque blob: it only copies the bytes as
 * provided by the caller.
 *
 * The resulting payload can later be parsed with dvco_cp_parse_keyfield_payload().
 *
 * Buffer contract
 * ---------------
 * The function uses the standard DVCO two-call sizing pattern through dvco_buf_t:
 *
 *   1) Size query:
 *      - set out->data = NULL
 *      - call the function
 *      - on success, out->len receives the required payload size
 *
 *   2) Build:
 *      - allocate at least out->len bytes
 *      - assign:
 *          out->data = <allocated buffer>
 *          out->cap  = <allocated capacity>
 *      - call the function again
 *      - on success, out->len receives the produced payload length
 *
 * dvco_buf_t semantics
 * --------------------
 * The function interprets dvco_buf_t as follows:
 *
 *   - out->data : pointer to the destination buffer
 *   - out->cap  : total capacity of the destination buffer in bytes
 *   - out->len  : output field; on return it contains either:
 *                 * the required size (size-query or BUFFER_TOO_SMALL), or
 *                 * the produced payload size on success
 *
 * Parameters
 * ----------
 * cid
 *   Cipher selector to be encoded in the first 2 bytes of the payload.
 *   The value is serialized in big-endian order.
 *
 * opaque
 *   Pointer to the provider-specific opaque binary blob.
 *   This pointer may be NULL only when opaque_len is 0.
 *
 * opaque_len
 *   Length, in bytes, of the opaque blob.
 *
 * out
 *   Output buffer descriptor.
 *   Must not be NULL.
 *
 * Return value
 * ------------
 * DVCO_CP_OK
 *   Success.
 *   - if out->data == NULL, out->len is set to the required payload length
 *   - otherwise the payload is written to out->data and out->len is set to the
 *     produced length
 *
 * DVCO_CP_ERR_INVALID_ARG
 *   Returned when:
 *   - out is NULL
 *   - opaque is NULL while opaque_len is non-zero
 *   - the computed total length would overflow size_t
 *
 * DVCO_CP_ERR_BUFFER_TOO_SMALL
 *   Returned when out->data is non-NULL but out->cap is smaller than the
 *   required payload size. In this case out->len is set to the required size.
 *
 * Payload size
 * ------------
 * The total size of the payload is:
 *
 *   2 + opaque_len
 *
 * since the CID always occupies 2 bytes.
 *
 * Notes
 * -----
 * - The function does not inspect, validate, or transform the opaque payload.
 * - The function does not allocate memory.
 * - The function does not append any terminator byte.
 * - The produced payload is a pure binary buffer and is not text-encoded.
 */

int dvco_cp_build_keyfield_payload(
    dvco_selector_t   cid,
    const uint8_t    *opaque,
    size_t            opaque_len,
    dvco_buf_t       *out
) {
    size_t total_len;
    uint8_t *p;

    if (out == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    /* opaque may be NULL only if opaque_len == 0 */
    if ((opaque == NULL) && (opaque_len != 0u)) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    /* Prevent overflow: total_len = 2 + opaque_len */
    if (opaque_len > (SIZE_MAX - 2u)) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    total_len = 2u + opaque_len;

    /*
     * Two-call sizing pattern:
     * - if out->data == NULL, return required size in out->len
     */
    if (out->data == NULL) {
        out->len = total_len;
        return DVCO_CP_OK;
    }

    if (out->cap < total_len) {
        out->len = total_len;
        return DVCO_CP_ERR_BUFFER_TOO_SMALL;
    }

    p = out->data;

    dvco_cp_u16_to_be((uint16_t)cid, p);

    if (opaque_len > 0u) {
        memcpy(p + 2u, opaque, opaque_len);
    }

    out->len = total_len;
    return DVCO_CP_OK;
}

int dvco_cp_parse_keyfield_payload(
    const uint8_t    *in_data,
    size_t            in_len,
    dvco_selector_t  *out_cid,
    const uint8_t   **out_opaque,
    size_t           *out_opaque_len
) {
    if (in_data == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (out_cid == NULL || out_opaque == NULL || out_opaque_len == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    /* Minimum format is [CID:2] */
    if (in_len < 2u) {
        return DVCO_CP_ERR_PARSE;
    }

    *out_cid = (dvco_selector_t)dvco_cp_u16_from_be(in_data);
    *out_opaque = in_data + 2u;
    *out_opaque_len = in_len - 2u;

    return DVCO_CP_OK;
}
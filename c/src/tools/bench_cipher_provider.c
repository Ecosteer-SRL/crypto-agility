// SPDX-FileCopyrightText: 2026 Daniel Grazioli (graz)
// SPDX-FileCopyrightText: 2026 Ecosteer srl
// SPDX-License-Identifier: MIT
// ver: 1.3

// bench_cipher_provider.c
//
// Linux benchmark harness for cipher providers.
//
// Purpose
// -------
// - Load one cipher provider at runtime from a shared library (.so)
// - Resolve dvco_cipher_provider_get_api()
// - Exercise the provider through the current cipher_provider.h vtable ABI
// - Measure provider-neutral encryption and decryption throughput
//
// Benchmark semantics
// -------------------
// - One benchmark tool must work with all cipher providers.
// - Encryption benchmark:
//     repeat N times:
//         encrypt prepared plaintext using one initialized encryption context
// - Decryption benchmark supports two modes:
//     reuse:
//         create decrypt context once
//         deserialize_shareable into decrypt context once
//         repeat N times:
//             decrypt reference ciphertext
//         destroy decrypt context
//     cycle:
//         repeat N times:
//             create decrypt context
//             deserialize_shareable into decrypt context
//             decrypt reference ciphertext
//             destroy decrypt context
// - reuse is the default mode and reflects the normal cipher-instance lifecycle.
// - cycle measures full decrypt-context lifecycle overhead.
//
// Notes
// -----
// - This tool is not a replacement for test_cipher_provider.c.
// - test_cipher_provider.c certifies provider compliance.
// - bench_cipher_provider.c measures provider throughput through the ABI path.
// - Ciphertext is treated as opaque provider output.
// - Provider-specific IV/nonce/tag/tweak/frame internals are not inspected.
// - Padding is applied/unapplied outside the provider, according to provider metadata,
//   exactly as the current test tool does.

#include "ciphers/cipher_provider.h"
#include "padding/dvco_padding.h"

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef DOP_SUCCESS
#define DOP_SUCCESS 0
#endif

#define BENCH_DEFAULT_SIZE 1024u
#define BENCH_DEFAULT_ITERS 100000u

typedef enum decrypt_mode_e {
    DECRYPT_MODE_REUSE = 0,
    DECRYPT_MODE_CYCLE = 1
} decrypt_mode_t;

typedef struct app_cfg_s {
    const char *lib_path;
    const char *confstring;
    size_t plain_len;
    size_t iters;
    decrypt_mode_t decrypt_mode;
} app_cfg_t;

typedef struct kv_list_s {
    dvco_kv_t *items;
    char      *storage;
    size_t     count;
} kv_list_t;

typedef struct bench_result_s {
    double enc_ms;
    double dec_ms;
    double total_ms;
    double enc_ops_sec;
    double dec_ops_sec;
    double enc_mib_sec;
    double dec_mib_sec;
} bench_result_t;

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s --cipher <provider.so> [--confstring \"k1=v1;k2=v2\"] [--size <bytes>] [--iters <n>] [--decrypt-mode <reuse|cycle>]\n"
        "\n"
        "Aliases:\n"
        "  --lib <provider.so> is accepted as an alias for --cipher\n"
        "\n"
        "Decrypt modes:\n"
        "  reuse  create one decrypt context, import shareable material once, decrypt N times\n"
        "  cycle  create/import/decrypt/destroy once per iteration\n"
        "\n"
        "Default decrypt mode:\n"
        "  reuse\n"
        "\n"
        "Examples:\n"
        "  %s --cipher ../../build/release/lib/libaes_gcm_provider.so --confstring \"\" --size 1024 --iters 100000 --decrypt-mode reuse\n",
        prog,
        prog
    );
}




static int parse_size_value(const char *s, size_t *out) {
    char *end = NULL;
    unsigned long long v;

    if (s == NULL || out == NULL || s[0] == '\0') {
        return -1;
    }

    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v == 0u) {
        return -1;
    }

    *out = (size_t)v;
    return 0;
}

static const char *decrypt_mode_to_string(decrypt_mode_t mode) {
    switch (mode) {
        case DECRYPT_MODE_REUSE:
            return "reuse";
        case DECRYPT_MODE_CYCLE:
            return "cycle";
        default:
            return "unknown";
    }
}

static int parse_decrypt_mode(const char *s, decrypt_mode_t *out) {
    if (s == NULL || out == NULL) {
        return -1;
    }

    if (strcmp(s, "reuse") == 0) {
        *out = DECRYPT_MODE_REUSE;
        return 0;
    }

    if (strcmp(s, "cycle") == 0) {
        *out = DECRYPT_MODE_CYCLE;
        return 0;
    }

    return -1;
}


static int parse_args(int argc, char **argv, app_cfg_t *cfg) {
    int i;

    if (cfg == NULL) {
        return -1;
    }

    memset(cfg, 0, sizeof(*cfg));
    cfg->confstring = "";
    cfg->plain_len = BENCH_DEFAULT_SIZE;
    cfg->iters = BENCH_DEFAULT_ITERS;
    cfg->decrypt_mode = DECRYPT_MODE_REUSE;

    for (i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "--cipher") == 0 || strcmp(argv[i], "--lib") == 0) && (i + 1) < argc) {
            cfg->lib_path = argv[++i];

        } else if (strcmp(argv[i], "--confstring") == 0 && (i + 1) < argc) {
            cfg->confstring = argv[++i];

        } else if (strcmp(argv[i], "--size") == 0 && (i + 1) < argc) {
            if (parse_size_value(argv[++i], &cfg->plain_len) != 0) {
                fprintf(stderr, "Invalid --size value\n");
                return -1;
            }

        } else if (strcmp(argv[i], "--iters") == 0 && (i + 1) < argc) {
            if (parse_size_value(argv[++i], &cfg->iters) != 0) {
                fprintf(stderr, "Invalid --iters value\n");
                return -1;
            }

        } else if (strcmp(argv[i], "--decrypt-mode") == 0 && (i + 1) < argc) {
            if (parse_decrypt_mode(argv[++i], &cfg->decrypt_mode) != 0) {
                fprintf(stderr, "Invalid --decrypt-mode value\n");
                return -1;
            }

        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 1;

        } else {
            fprintf(stderr, "Unknown or incomplete argument: %s\n", argv[i]);
            usage(argv[0]);
            return -1;
        }
    }

    if (cfg->lib_path == NULL) {
        fprintf(stderr, "Missing required --cipher argument\n");
        usage(argv[0]);
        return -1;
    }

    return 0;
}


static char *trim_inplace(char *s) {
    char *end;

    if (s == NULL) {
        return NULL;
    }

    while (*s != '\0' && isspace((unsigned char)*s)) {
        s++;
    }

    if (*s == '\0') {
        return s;
    }

    end = s + strlen(s) - 1u;
    while (end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    return s;
}

static void free_kv_list(kv_list_t *kv) {
    if (kv == NULL) {
        return;
    }

    free(kv->items);
    free(kv->storage);

    kv->items = NULL;
    kv->storage = NULL;
    kv->count = 0u;
}

static int parse_confstring(const char *confstring, kv_list_t *out_kv) {
    size_t i;
    size_t pairs_max;
    char *cursor;
    char *segment;

    if (out_kv == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    memset(out_kv, 0, sizeof(*out_kv));

    if (confstring == NULL || confstring[0] == '\0') {
        return DVCO_CP_OK;
    }

    pairs_max = 1u;
    for (i = 0u; confstring[i] != '\0'; i++) {
        if (confstring[i] == ';') {
            pairs_max++;
        }
    }

    out_kv->storage = (char *)malloc(strlen(confstring) + 1u);
    if (out_kv->storage == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }
    strcpy(out_kv->storage, confstring);

    out_kv->items = (dvco_kv_t *)calloc(pairs_max, sizeof(dvco_kv_t));
    if (out_kv->items == NULL) {
        free_kv_list(out_kv);
        return DVCO_CP_ERR_ALLOC;
    }

    cursor = out_kv->storage;

    while (cursor != NULL && *cursor != '\0') {
        char *sep = strchr(cursor, ';');
        char *eq;
        char *key;
        char *value;

        if (sep != NULL) {
            *sep = '\0';
            segment = cursor;
            cursor = sep + 1;
        } else {
            segment = cursor;
            cursor = NULL;
        }

        segment = trim_inplace(segment);
        if (*segment == '\0') {
            continue;
        }

        eq = strchr(segment, '=');
        if (eq == NULL) {
            free_kv_list(out_kv);
            return DVCO_CP_ERR_PARSE;
        }

        *eq = '\0';
        key = trim_inplace(segment);
        value = trim_inplace(eq + 1);

        if (*key == '\0') {
            free_kv_list(out_kv);
            return DVCO_CP_ERR_PARSE;
        }

        out_kv->items[out_kv->count].key = key;
        out_kv->items[out_kv->count].value = value;
        out_kv->count++;
    }

    return DVCO_CP_OK;
}

static void secure_zero_free(uint8_t *p, size_t n) {
    if (p != NULL) {
        if (n > 0u) {
            memset(p, 0, n);
        }
        free(p);
    }
}

static double elapsed_ms(const struct timespec *a, const struct timespec *b) {
    double sec;
    double nsec;

    sec = (double)(b->tv_sec - a->tv_sec);
    nsec = (double)(b->tv_nsec - a->tv_nsec);

    return (sec * 1000.0) + (nsec / 1000000.0);
}

static void fill_plaintext(uint8_t *p, size_t n) {
    size_t i;

    if (p == NULL) {
        return;
    }

    for (i = 0u; i < n; i++) {
        p[i] = (uint8_t)(i & 0xffu);
    }
}

static void print_provider_last_error(const dvco_cipher_provider_api_t *api, dvco_cipher_ctx_t *ctx) {
    const char *s;

    if (api == NULL || api->last_error == NULL) {
        return;
    }

    s = api->last_error(ctx);
    if (s != NULL && s[0] != '\0') {
        fprintf(stderr, "provider last_error: %s\n", s);
    }
}

static void print_provider_op_error(const char *op, int rc, const dvco_cipher_provider_api_t *api, dvco_cipher_ctx_t *ctx) {
    fprintf(stderr, "%s failed: rc=%d\n", op, rc);
    print_provider_last_error(api, ctx);
}

static int alloc_pad_if_needed(
    const dvco_cipher_provider_info_t *info,
    const uint8_t *plain,
    size_t plain_len,
    uint8_t **enc_in,
    size_t *enc_in_len
) {
    int rc;
    uint8_t *buf = NULL;
    size_t block_size;
    size_t pad_len;
    size_t out_len;

    if (info == NULL || enc_in == NULL || enc_in_len == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *enc_in = NULL;
    *enc_in_len = 0u;

    if ((plain_len > 0u) && (plain == NULL)) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (info->pad_apply == false) {
        buf = (uint8_t *)malloc(plain_len > 0u ? plain_len : 1u);
        if (buf == NULL) {
            return DVCO_CP_ERR_ALLOC;
        }
        if (plain_len > 0u) {
            memcpy(buf, plain, plain_len);
        }
        *enc_in = buf;
        *enc_in_len = plain_len;
        return DVCO_CP_OK;
    }

    block_size = info->pad_block_size;
    if (block_size == 0u) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    pad_len = block_size - (plain_len % block_size);
    if (pad_len == 0u) {
        pad_len = block_size;
    }

    out_len = plain_len + pad_len;

    buf = (uint8_t *)malloc(out_len);
    if (buf == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }

    rc = dvco_pkcs7_pad(plain, plain_len, buf, &out_len, block_size);
    if (rc != DOP_SUCCESS) {
        free(buf);
        return rc;
    }

    *enc_in = buf;
    *enc_in_len = out_len;
    return DVCO_CP_OK;
}

static int alloc_unpad_if_needed(
    const dvco_cipher_provider_info_t *info,
    const uint8_t *plain_in,
    size_t plain_in_len,
    uint8_t **plain_out,
    size_t *plain_out_len
) {
    int rc;
    uint8_t *buf = NULL;
    size_t len;

    if (info == NULL || plain_out == NULL || plain_out_len == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *plain_out = NULL;
    *plain_out_len = 0u;

    buf = (uint8_t *)malloc(plain_in_len > 0u ? plain_in_len : 1u);
    if (buf == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }

    if (plain_in_len > 0u) {
        memcpy(buf, plain_in, plain_in_len);
    }

    len = plain_in_len;

    if (info->pad_apply) {
        rc = dvco_pkcs7_unpad(buf, &len, info->pad_block_size);
        if (rc != DOP_SUCCESS) {
            free(buf);
            return rc;
        }
    }

    *plain_out = buf;
    *plain_out_len = len;
    return DVCO_CP_OK;
}

static int alloc_via_provider_2call(
    int (*fn)(dvco_cipher_ctx_t *, dvco_buf_t *),
    dvco_cipher_ctx_t *ctx,
    uint8_t **out_buf,
    size_t *out_len
) {
    dvco_buf_t b;
    int rc;

    if (fn == NULL || ctx == NULL || out_buf == NULL || out_len == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_buf = NULL;
    *out_len = 0u;

    b.data = NULL;
    b.len = 0u;
    b.cap = 0u;

    rc = fn(ctx, &b);
    if (rc != DVCO_CP_OK) {
        return rc;
    }

    if (b.len == 0u) {
        return DVCO_CP_ERR_GENERIC;
    }

    b.data = (uint8_t *)malloc(b.len);
    if (b.data == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }
    b.cap = b.len;

    rc = fn(ctx, &b);
    if (rc != DVCO_CP_OK) {
        free(b.data);
        return rc;
    }

    *out_buf = b.data;
    *out_len = b.len;
    return DVCO_CP_OK;
}

static int alloc_encrypt_2call(
    const dvco_cipher_provider_api_t *api,
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    uint8_t **out_buf,
    size_t *out_len
) {
    dvco_buf_t b;
    int rc;

    if (api == NULL || api->encrypt == NULL || ctx == NULL || out_buf == NULL || out_len == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_buf = NULL;
    *out_len = 0u;

    b.data = NULL;
    b.len = 0u;
    b.cap = 0u;

    rc = api->encrypt(ctx, in_data, in_len, NULL, 0u, &b);
    if (rc != DVCO_CP_OK) {
        return rc;
    }

    if (b.len == 0u) {
        return DVCO_CP_ERR_GENERIC;
    }

    b.data = (uint8_t *)malloc(b.len);
    if (b.data == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }
    b.cap = b.len;

    rc = api->encrypt(ctx, in_data, in_len, NULL, 0u, &b);
    if (rc != DVCO_CP_OK) {
        free(b.data);
        return rc;
    }

    *out_buf = b.data;
    *out_len = b.len;
    return DVCO_CP_OK;
}

static int alloc_decrypt_2call(
    const dvco_cipher_provider_api_t *api,
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    uint8_t **out_buf,
    size_t *out_len
) {
    dvco_buf_t b;
    int rc;

    if (api == NULL || api->decrypt == NULL || ctx == NULL || out_buf == NULL || out_len == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_buf = NULL;
    *out_len = 0u;

    b.data = NULL;
    b.len = 0u;
    b.cap = 0u;

    rc = api->decrypt(ctx, in_data, in_len, NULL, 0u, &b);
    if (rc != DVCO_CP_OK) {
        return rc;
    }

    if (b.len == 0u) {
        return DVCO_CP_ERR_GENERIC;
    }

    b.data = (uint8_t *)malloc(b.len);
    if (b.data == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }
    b.cap = b.len;

    rc = api->decrypt(ctx, in_data, in_len, NULL, 0u, &b);
    if (rc != DVCO_CP_OK) {
        free(b.data);
        return rc;
    }

    *out_buf = b.data;
    *out_len = b.len;
    return DVCO_CP_OK;
}

static int run_encrypt_bench(
    const dvco_cipher_provider_api_t *api,
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    uint8_t *cipher_buf,
    size_t cipher_cap,
    size_t iters,
    bench_result_t *res
) {
    struct timespec t0;
    struct timespec t1;
    dvco_buf_t out;
    size_t i;
    int rc;
    double seconds;
    double total_bytes;

    if (api == NULL || api->encrypt == NULL || ctx == NULL || in_data == NULL || cipher_buf == NULL || res == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &t0) != 0) {
        perror("clock_gettime encrypt start");
        return DVCO_CP_ERR_GENERIC;
    }

    for (i = 0u; i < iters; i++) {
        out.data = cipher_buf;
        out.len = cipher_cap;
        out.cap = cipher_cap;

        rc = api->encrypt(ctx, in_data, in_len, NULL, 0u, &out);
        if (rc != DVCO_CP_OK) {
            return rc;
        }
    }

    if (clock_gettime(CLOCK_MONOTONIC, &t1) != 0) {
        perror("clock_gettime encrypt stop");
        return DVCO_CP_ERR_GENERIC;
    }

    res->enc_ms = elapsed_ms(&t0, &t1);
    seconds = res->enc_ms / 1000.0;
    total_bytes = (double)in_len * (double)iters;

    if (seconds > 0.0) {
        res->enc_ops_sec = (double)iters / seconds;
        res->enc_mib_sec = total_bytes / seconds / 1024.0 / 1024.0;
    }

    return DVCO_CP_OK;
}

static int run_decrypt_reuse_bench(
    const dvco_cipher_provider_api_t *api,
    const dvco_kv_t *cfg_items,
    size_t cfg_count,
    const uint8_t *shareable,
    size_t shareable_len,
    const uint8_t *cipher_data,
    size_t cipher_len,
    uint8_t *plain_buf,
    size_t plain_cap,
    size_t measured_plain_len,
    size_t iters,
    bench_result_t *res
) {
    struct timespec t0;
    struct timespec t1;
    dvco_cipher_ctx_t *ctx = NULL;
    dvco_buf_t out;
    size_t i;
    int rc;
    double seconds;
    double total_bytes;

    if (api == NULL ||
        api->create == NULL ||
        api->destroy == NULL ||
        api->deserialize_shareable == NULL ||
        api->decrypt == NULL ||
        shareable == NULL ||
        cipher_data == NULL ||
        plain_buf == NULL ||
        res == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    rc = api->create(cfg_items, cfg_count, &ctx);
    if (rc != DVCO_CP_OK || ctx == NULL) {
        if (ctx != NULL) {
            api->destroy(ctx);
        }
        return rc;
    }

    rc = api->deserialize_shareable(ctx, shareable, shareable_len);
    if (rc != DVCO_CP_OK) {
        api->destroy(ctx);
        return rc;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &t0) != 0) {
        perror("clock_gettime decrypt start");
        api->destroy(ctx);
        return DVCO_CP_ERR_GENERIC;
    }

    for (i = 0u; i < iters; i++) {
        out.data = plain_buf;
        out.len = plain_cap;
        out.cap = plain_cap;

        rc = api->decrypt(ctx, cipher_data, cipher_len, NULL, 0u, &out);
        if (rc != DVCO_CP_OK) {
            api->destroy(ctx);
            return rc;
        }
    }

    if (clock_gettime(CLOCK_MONOTONIC, &t1) != 0) {
        perror("clock_gettime decrypt stop");
        api->destroy(ctx);
        return DVCO_CP_ERR_GENERIC;
    }

    api->destroy(ctx);

    res->dec_ms = elapsed_ms(&t0, &t1);
    seconds = res->dec_ms / 1000.0;
    total_bytes = (double)measured_plain_len * (double)iters;

    if (seconds > 0.0) {
        res->dec_ops_sec = (double)iters / seconds;
        res->dec_mib_sec = total_bytes / seconds / 1024.0 / 1024.0;
    }

    return DVCO_CP_OK;
}

static int run_decrypt_cycle_bench(
    const dvco_cipher_provider_api_t *api,
    const dvco_kv_t *cfg_items,
    size_t cfg_count,
    const uint8_t *shareable,
    size_t shareable_len,
    const uint8_t *cipher_data,
    size_t cipher_len,
    uint8_t *plain_buf,
    size_t plain_cap,
    size_t measured_plain_len,
    size_t iters,
    bench_result_t *res
) {
    struct timespec t0;
    struct timespec t1;
    dvco_buf_t out;
    size_t i;
    int rc;
    double seconds;
    double total_bytes;

    if (api == NULL ||
        api->create == NULL ||
        api->destroy == NULL ||
        api->deserialize_shareable == NULL ||
        api->decrypt == NULL ||
        shareable == NULL ||
        cipher_data == NULL ||
        plain_buf == NULL ||
        res == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &t0) != 0) {
        perror("clock_gettime decrypt cycle start");
        return DVCO_CP_ERR_GENERIC;
    }

    for (i = 0u; i < iters; i++) {
        dvco_cipher_ctx_t *ctx = NULL;

        rc = api->create(cfg_items, cfg_count, &ctx);
        if (rc != DVCO_CP_OK || ctx == NULL) {
            if (ctx != NULL) {
                api->destroy(ctx);
            }
            return rc;
        }

        rc = api->deserialize_shareable(ctx, shareable, shareable_len);
        if (rc != DVCO_CP_OK) {
            api->destroy(ctx);
            return rc;
        }

        out.data = plain_buf;
        out.len = plain_cap;
        out.cap = plain_cap;

        rc = api->decrypt(ctx, cipher_data, cipher_len, NULL, 0u, &out);

        api->destroy(ctx);

        if (rc != DVCO_CP_OK) {
            return rc;
        }
    }

    if (clock_gettime(CLOCK_MONOTONIC, &t1) != 0) {
        perror("clock_gettime decrypt cycle stop");
        return DVCO_CP_ERR_GENERIC;
    }

    res->dec_ms = elapsed_ms(&t0, &t1);
    seconds = res->dec_ms / 1000.0;
    total_bytes = (double)measured_plain_len * (double)iters;

    if (seconds > 0.0) {
        res->dec_ops_sec = (double)iters / seconds;
        res->dec_mib_sec = total_bytes / seconds / 1024.0 / 1024.0;
    }

    return DVCO_CP_OK;
}

static void print_results(
    const app_cfg_t *cfg,
    const dvco_cipher_provider_info_t *info,
    size_t encrypt_input_len,
    size_t ciphertext_len,
    const bench_result_t *res
) {
    printf("provider              : %s\n", info->provider_name ? info->provider_name : "(null)");
    printf("version               : %s\n", info->provider_version ? info->provider_version : "(null)");
    printf("cid                   : %u\n", (unsigned)info->cid);
    printf("abi                   : %u.%u\n", info->abi_major, info->abi_minor);
    printf("pad_apply             : %s\n", info->pad_apply ? "true" : "false");
    printf("pad_block_size        : %zu\n", info->pad_block_size);
    printf("cleartext size        : %zu bytes\n", cfg->plain_len);
    printf("encrypt input size    : %zu bytes\n", encrypt_input_len);
    printf("ciphertext size       : %zu bytes\n", ciphertext_len);
    printf("iterations            : %zu\n", cfg->iters);
    printf("decrypt mode          : %s\n", decrypt_mode_to_string(cfg->decrypt_mode));
    printf("\n");
    printf("encrypt time          : %.3f ms\n", res->enc_ms);
    if (cfg->decrypt_mode == DECRYPT_MODE_CYCLE) {
        printf("decrypt cycle time    : %.3f ms\n", res->dec_ms);
    } else {
        printf("decrypt time          : %.3f ms\n", res->dec_ms);
    }
    printf("total time            : %.3f ms\n", res->total_ms);
    printf("\n");
    printf("encrypt ops/s         : %.2f\n", res->enc_ops_sec);
    if (cfg->decrypt_mode == DECRYPT_MODE_CYCLE) {
        printf("decrypt cycles/s      : %.2f\n", res->dec_ops_sec);
    } else {
        printf("decrypt ops/s         : %.2f\n", res->dec_ops_sec);
    }
    printf("\n");
    printf("encrypt MiB/s         : %.2f\n", res->enc_mib_sec);
    if (cfg->decrypt_mode == DECRYPT_MODE_CYCLE) {
        printf("decrypt cycle MiB/s   : %.2f\n", res->dec_mib_sec);
    } else {
        printf("decrypt MiB/s         : %.2f\n", res->dec_mib_sec);
    }
}

int main(int argc, char **argv) {
    app_cfg_t cfg;
    kv_list_t kv = {0};

    void *dl_handle = NULL;
    dvco_cipher_provider_get_api_fn get_api_fn = NULL;
    const dvco_cipher_provider_api_t *api = NULL;
    dvco_cipher_provider_info_t info;

    dvco_cipher_ctx_t *ctx_enc = NULL;
    dvco_cipher_ctx_t *ctx_dec_check = NULL;

    uint8_t *plain = NULL;
    uint8_t *encrypt_input = NULL;
    uint8_t *shareable = NULL;
    uint8_t *ciphertext_ref = NULL;
    uint8_t *ciphertext_work = NULL;
    uint8_t *decrypted_raw = NULL;
    uint8_t *decrypted_cmp = NULL;
    uint8_t *bench_decrypt_buf = NULL;

    size_t encrypt_input_len = 0u;
    size_t shareable_len = 0u;
    size_t ciphertext_ref_len = 0u;
    size_t ciphertext_work_cap = 0u;
    size_t decrypted_raw_len = 0u;
    size_t decrypted_cmp_len = 0u;
    size_t bench_decrypt_cap = 0u;

    bench_result_t res;
    int rc;
    int exit_code = 1;

    memset(&info, 0, sizeof(info));
    memset(&res, 0, sizeof(res));

    rc = parse_args(argc, argv, &cfg);
    if (rc != 0) {
        return (rc > 0) ? 0 : 1;
    }

    rc = parse_confstring(cfg.confstring, &kv);
    if (rc != DVCO_CP_OK) {
        fprintf(stderr, "Invalid confstring: %s\n", cfg.confstring ? cfg.confstring : "(null)");
        goto done;
    }

    plain = (uint8_t *)malloc(cfg.plain_len > 0u ? cfg.plain_len : 1u);
    if (plain == NULL) {
        fprintf(stderr, "malloc plaintext failed\n");
        goto done;
    }
    fill_plaintext(plain, cfg.plain_len);

    dl_handle = dlopen(cfg.lib_path, RTLD_NOW);
    if (dl_handle == NULL) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        goto done;
    }

    get_api_fn = (dvco_cipher_provider_get_api_fn)dlsym(dl_handle, DVCO_CIPHER_PROVIDER_GET_API_SYMBOL);
    if (get_api_fn == NULL) {
        fprintf(stderr, "dlsym failed for symbol %s: %s\n", DVCO_CIPHER_PROVIDER_GET_API_SYMBOL, dlerror());
        goto done;
    }

    rc = get_api_fn(&api);
    if (rc != DVCO_CP_OK || api == NULL) {
        fprintf(stderr, "dvco_cipher_provider_get_api failed: rc=%d\n", rc);
        goto done;
    }

    if (api->get_info == NULL ||
        api->create == NULL ||
        api->destroy == NULL ||
        api->rotate == NULL ||
        api->serialize_shareable == NULL ||
        api->deserialize_shareable == NULL ||
        api->encrypt == NULL ||
        api->decrypt == NULL) {
        fprintf(stderr, "Provider API is incomplete\n");
        goto done;
    }

    rc = api->get_info(&info);
    if (rc != DVCO_CP_OK) {
        print_provider_op_error("get_info", rc, api, NULL);
        goto done;
    }

    rc = api->create(kv.items, kv.count, &ctx_enc);
    if (rc != DVCO_CP_OK || ctx_enc == NULL) {
        print_provider_op_error("create(ctx_enc)", rc, api, ctx_enc);
        goto done;
    }

    rc = api->create(kv.items, kv.count, &ctx_dec_check);
    if (rc != DVCO_CP_OK || ctx_dec_check == NULL) {
        print_provider_op_error("create(ctx_dec_check)", rc, api, ctx_dec_check);
        goto done;
    }

    if (api->reset != NULL) {
        rc = api->reset(ctx_enc);
        if (rc != DVCO_CP_OK) {
            print_provider_op_error("reset(ctx_enc)", rc, api, ctx_enc);
            goto done;
        }
    }

    rc = api->rotate(ctx_enc);
    if (rc != DVCO_CP_OK) {
        print_provider_op_error("rotate(ctx_enc)", rc, api, ctx_enc);
        goto done;
    }

    rc = alloc_via_provider_2call(api->serialize_shareable, ctx_enc, &shareable, &shareable_len);
    if (rc != DVCO_CP_OK) {
        print_provider_op_error("serialize_shareable(ctx_enc)", rc, api, ctx_enc);
        goto done;
    }

    rc = api->deserialize_shareable(ctx_dec_check, shareable, shareable_len);
    if (rc != DVCO_CP_OK) {
        print_provider_op_error("deserialize_shareable(ctx_dec_check)", rc, api, ctx_dec_check);
        goto done;
    }

    rc = alloc_pad_if_needed(&info, plain, cfg.plain_len, &encrypt_input, &encrypt_input_len);
    if (rc != DVCO_CP_OK) {
        fprintf(stderr, "prepare encrypt input failed: rc=%d\n", rc);
        goto done;
    }

    rc = alloc_encrypt_2call(api, ctx_enc, encrypt_input, encrypt_input_len, &ciphertext_ref, &ciphertext_ref_len);
    if (rc != DVCO_CP_OK) {
        print_provider_op_error("encrypt(correctness)", rc, api, ctx_enc);
        goto done;
    }

    rc = alloc_decrypt_2call(api, ctx_dec_check, ciphertext_ref, ciphertext_ref_len, &decrypted_raw, &decrypted_raw_len);
    if (rc != DVCO_CP_OK) {
        print_provider_op_error("decrypt(correctness)", rc, api, ctx_dec_check);
        goto done;
    }

    rc = alloc_unpad_if_needed(&info, decrypted_raw, decrypted_raw_len, &decrypted_cmp, &decrypted_cmp_len);
    if (rc != DVCO_CP_OK) {
        fprintf(stderr, "normalize decrypted failed: rc=%d\n", rc);
        goto done;
    }

    if (decrypted_cmp_len != cfg.plain_len || memcmp(decrypted_cmp, plain, cfg.plain_len) != 0) {
        fprintf(stderr, "Roundtrip mismatch: decrypted payload differs from input\n");
        goto done;
    }

    bench_decrypt_cap = decrypted_raw_len;
    bench_decrypt_buf = (uint8_t *)malloc(bench_decrypt_cap > 0u ? bench_decrypt_cap : 1u);
    if (bench_decrypt_buf == NULL) {
        fprintf(stderr, "malloc decrypt benchmark buffer failed\n");
        goto done;
    }

    ciphertext_work_cap = ciphertext_ref_len;
    ciphertext_work = (uint8_t *)malloc(ciphertext_work_cap > 0u ? ciphertext_work_cap : 1u);
    if (ciphertext_work == NULL) {
        fprintf(stderr, "malloc encrypt benchmark buffer failed\n");
        goto done;
    }

    rc = run_encrypt_bench(
        api,
        ctx_enc,
        encrypt_input,
        encrypt_input_len,
        ciphertext_work,
        ciphertext_work_cap,
        cfg.iters,
        &res
    );
    if (rc != DVCO_CP_OK) {
        print_provider_op_error("encrypt benchmark", rc, api, ctx_enc);
        goto done;
    }

    if (cfg.decrypt_mode == DECRYPT_MODE_CYCLE) {
        rc = run_decrypt_cycle_bench(
            api,
            kv.items,
            kv.count,
            shareable,
            shareable_len,
            ciphertext_ref,
            ciphertext_ref_len,
            bench_decrypt_buf,
            bench_decrypt_cap,
            encrypt_input_len,
            cfg.iters,
            &res
        );
    } else {
        rc = run_decrypt_reuse_bench(
            api,
            kv.items,
            kv.count,
            shareable,
            shareable_len,
            ciphertext_ref,
            ciphertext_ref_len,
            bench_decrypt_buf,
            bench_decrypt_cap,
            encrypt_input_len,
            cfg.iters,
            &res
        );
    }
    if (rc != DVCO_CP_OK) {
        print_provider_op_error("decrypt benchmark", rc, api, NULL);
        goto done;
    }

    res.total_ms = res.enc_ms + res.dec_ms;
    print_results(&cfg, &info, encrypt_input_len, ciphertext_ref_len, &res);

    exit_code = 0;

done:
    secure_zero_free(plain, cfg.plain_len);
    secure_zero_free(encrypt_input, encrypt_input_len);
    secure_zero_free(decrypted_cmp, decrypted_cmp_len);
    secure_zero_free(bench_decrypt_buf, bench_decrypt_cap);
    secure_zero_free(ciphertext_work, ciphertext_work_cap);

    free(shareable);
    free(ciphertext_ref);
    free(decrypted_raw);

    if (api != NULL && ctx_enc != NULL && api->destroy != NULL) {
        api->destroy(ctx_enc);
    }
    if (api != NULL && ctx_dec_check != NULL && api->destroy != NULL) {
        api->destroy(ctx_dec_check);
    }
    if (dl_handle != NULL) {
        dlclose(dl_handle);
    }

    free_kv_list(&kv);
    return exit_code;
}

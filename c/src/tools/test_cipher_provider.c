// SPDX-FileCopyrightText: 2026 Daniel Grazioli (graz)
// SPDX-FileCopyrightText: 2026 Ecosteer srl
// SPDX-License-Identifier: MIT
// ver: 1.0

/*
 * test_cipher_provider.c
 *
 * Linux reference test harness for DVCO cipher providers.
 *
 * Purpose
 * -------
 * - Load a cipher provider at runtime from a shared library (.so)
 * - Resolve dvco_cipher_provider_get_api()
 * - Exercise the provider vtable end-to-end with the rotation flow:
 *     get_info
 *     create(confstring)
 *     rotate()
 *     encrypt
 *     serialize_shareable
 *     deserialize_shareable
 *     compare_shareable
 *     serialize_private
 *     deserialize_private
 *     compare_private
 *     decrypt
 *     last_error
 *     destroy
 *
 * Generic config model
 * --------------------
 * The loader accepts a single provider-agnostic confstring for create():
 *
 *   --confstring "k1=v1;k2=v2;...;kn=vn"
 *
 * Example (AES-CBC):
 *   ./build/release/bin/test_cipher_provider \
 *      --lib ./build/release/lib/libaes_cbc_provider.so \
 *      --confstring "keybits=256" \
 *      --plain "hello dvco"
 *
 * Example (Blowfish-ECB):
 *   ./build/release/bin/test_cipher_provider \
 *      --lib ./build/release/lib/libblowfish_ecb_provider.so \
 *      --confstring "keybits=384" \
 *      --plain "hello dvco"
 *
 *   ./build/release/bin/test_cipher_provider \
 *      --lib ./build/release/lib/libblowfish_ecb_provider.so \
 *      --confstring "key=0xabc48787d0d1ffff" \
 *      --plain "hello dvco"
 *
 * Notes:
 * - The loader is provider-generic: it does not know provider-specific keys.
 * - rotate() is called with no parameters.
 * - Simple v1 parser: keys/values must not contain ';' or '='.
 * - cid is provided by the provider implementation through get_info().
 * - iid is no longer part of the provider model and is not handled here.
 */

#include "ciphers/cipher_provider.h"
#include "padding/dvco_padding.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <ctype.h>


#ifndef DOP_SUCCESS
#define DOP_SUCCESS 0
#endif

typedef struct app_cfg_s {
    const char *lib_path;
    const char *confstring;
    const char *plain;
} app_cfg_t;

typedef struct kv_list_s {
    dvco_kv_t *items;
    char      *storage;
    size_t     count;
} kv_list_t;



static void secure_zero_free(uint8_t *p, size_t n) {
    if (p != NULL) {
        if (n > 0u) {
            memset(p, 0, n);
        }
        free(p);
    }
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

static void print_cmp_rc(const char *what, int rc) {
    if (rc == 0) {
        printf("%s: MATCH\n", what);
    } else if (rc > 0) {
        printf("%s: DIFFER\n", what);
    } else {
        printf("%s: rc=%d\n", what, rc);
    }
}


static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s --lib <provider.so> [--confstring \"k1=v1;k2=v2;...\"] [--plain <text>]\n"
        "\n"
        "Examples:\n"
        "  %s --lib ./build/release/lib/libaes_cbc_provider.so \\\n"
        "     --confstring \"keybits=256\" \\\n"
        "     --plain \"hello dvco\"\n",
        prog, prog
    );
}

static int parse_args(int argc, char **argv, app_cfg_t *cfg) {
    int i;

    if (cfg == NULL) {
        return -1;
    }

    memset(cfg, 0, sizeof(*cfg));
    cfg->plain = "hello dvco";
    cfg->confstring = "";

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--lib") == 0 && (i + 1) < argc) {
            cfg->lib_path = argv[++i];
        } else if (strcmp(argv[i], "--confstring") == 0 && (i + 1) < argc) {
            cfg->confstring = argv[++i];
        } else if (strcmp(argv[i], "--plain") == 0 && (i + 1) < argc) {
            cfg->plain = argv[++i];
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
        fprintf(stderr, "Missing required --lib argument\n");
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

    end = s + strlen(s) - 1;
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
    size_t pairs_max = 0u;
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

static void dump_hex(const char *label, const uint8_t *p, size_t n) {
    size_t i;

    printf("%s (%zu bytes): ", label, n);
    for (i = 0; i < n; i++) {
        printf("%02X", p[i]);
        if (i + 1u < n) {
            printf(" ");
        }
    }
    printf("\n");
}

static void print_rc(const char *what, int rc) {
    printf("%s: rc=%d\n", what, rc);
}

static void print_provider_last_error(const dvco_cipher_provider_api_t *api, dvco_cipher_ctx_t *ctx) {
    const char *s;

    if (api == NULL || api->last_error == NULL) {
        return;
    }

    s = api->last_error(ctx);
    if (s != NULL && s[0] != '\0') {
        printf("provider last_error: %s\n", s);
    }
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
    b.len  = 0u;
    b.cap  = 0u;

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
    b.len  = 0u;
    b.cap  = 0u;

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
    b.len  = 0u;
    b.cap  = 0u;

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



int main(int argc, char **argv) {
    app_cfg_t cfg;
    kv_list_t kv = {0};

    void *dl_handle = NULL;
    dvco_cipher_provider_get_api_fn get_api_fn = NULL;
    const dvco_cipher_provider_api_t *api = NULL;
    dvco_cipher_provider_info_t info;

    dvco_cipher_ctx_t *ctx_a = NULL;
    dvco_cipher_ctx_t *ctx_b = NULL;
    dvco_cipher_ctx_t *ctx_c = NULL;

    uint8_t *encrypt_input = NULL;
    size_t   encrypt_input_len = 0u;

    uint8_t *plaintext_cmp = NULL;
    size_t   plaintext_cmp_len = 0u;

    uint8_t *shareable = NULL;
    size_t   shareable_len = 0u;

    uint8_t *private_blob = NULL;
    size_t   private_blob_len = 0u;

    uint8_t *ciphertext = NULL;
    size_t   ciphertext_len = 0u;

    uint8_t *plaintext_out = NULL;
    size_t   plaintext_out_len = 0u;

    const char *plain_text = NULL;
    const uint8_t *plain_bytes = NULL;
    size_t plain_len = 0u;

    int rc;
    int exit_code = 1;

    memset(&info, 0, sizeof(info));

    rc = parse_args(argc, argv, &cfg);
    if (rc != 0) {
        return (rc > 0) ? 0 : 1;
    }

    rc = parse_confstring(cfg.confstring, &kv);
    print_rc("parse_confstring", rc);
    if (rc != DVCO_CP_OK) {
        fprintf(stderr, "Invalid confstring: %s\n", cfg.confstring ? cfg.confstring : "(null)");
        goto done;
    }

    plain_text  = cfg.plain;
    plain_bytes = (const uint8_t *)plain_text;
    plain_len   = strlen(plain_text);

    printf("Loading provider: %s\n", cfg.lib_path);

    dl_handle = dlopen(cfg.lib_path, RTLD_NOW);
    if (dl_handle == NULL) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        goto done;
    }

    get_api_fn = (dvco_cipher_provider_get_api_fn)dlsym(dl_handle, DVCO_CIPHER_PROVIDER_GET_API_SYMBOL);
    if (get_api_fn == NULL) {
        fprintf(stderr, "dlsym failed for symbol %s: %s\n",
                DVCO_CIPHER_PROVIDER_GET_API_SYMBOL, dlerror());
        goto done;
    }

    rc = get_api_fn(&api);
    print_rc("dvco_cipher_provider_get_api", rc);
    if (rc != DVCO_CP_OK || api == NULL) {
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
    print_rc("get_info", rc);
    if (rc != DVCO_CP_OK) {
        goto done;
    }

    printf("Provider info:\n");
    printf("  abi      : %u.%u\n", info.abi_major, info.abi_minor);
    printf("  name     : %s\n", info.provider_name ? info.provider_name : "(null)");
    printf("  version  : %s\n", info.provider_version ? info.provider_version : "(null)");
    printf("  desc     : %s\n", info.provider_desc ? info.provider_desc : "(null)");
    printf("  meta cid : %u\n", (unsigned)info.cid);
    printf("  pad_apply: %s\n", info.pad_apply ? "true" : "false");
    printf("  pad_block_size: %zu\n", info.pad_block_size);

    rc = api->create(kv.items, kv.count, &ctx_a);
    print_rc("create(ctx_a)", rc);
    if (rc != DVCO_CP_OK || ctx_a == NULL) {
        print_provider_last_error(api, ctx_a);
        goto done;
    }

    rc = api->create(kv.items, kv.count, &ctx_b);
    print_rc("create(ctx_b)", rc);
    if (rc != DVCO_CP_OK || ctx_b == NULL) {
        print_provider_last_error(api, ctx_b);
        goto done;
    }

    if (api->reset != NULL) {
        rc = api->reset(ctx_a);
        print_rc("reset(ctx_a)", rc);
        if (rc != DVCO_CP_OK) {
            print_provider_last_error(api, ctx_a);
            goto done;
        }
    }

    rc = api->rotate(ctx_a);
    print_rc("rotate(ctx_a)", rc);
    if (rc != DVCO_CP_OK) {
        print_provider_last_error(api, ctx_a);
        goto done;
    }

    printf("plaintext: \"%s\" (%zu bytes)\n", plain_text, plain_len);

    rc = alloc_pad_if_needed(&info, plain_bytes, plain_len, &encrypt_input, &encrypt_input_len);
    print_rc("prepare_encrypt_input", rc);
    if (rc != DVCO_CP_OK) {
        goto done;
    }

    dump_hex("encrypt_input", encrypt_input, encrypt_input_len);

    rc = alloc_encrypt_2call(api, ctx_a, encrypt_input, encrypt_input_len, &ciphertext, &ciphertext_len);
    print_rc("encrypt(ctx_a)", rc);
    if (rc != DVCO_CP_OK) {
        print_provider_last_error(api, ctx_a);
        goto done;
    }
    dump_hex("ciphertext", ciphertext, ciphertext_len);

    rc = alloc_via_provider_2call(api->serialize_shareable, ctx_a, &shareable, &shareable_len);
    print_rc("serialize_shareable(ctx_a)", rc);
    if (rc != DVCO_CP_OK) {
        print_provider_last_error(api, ctx_a);
        goto done;
    }
    dump_hex("shareable", shareable, shareable_len);

    rc = api->deserialize_shareable(ctx_b, shareable, shareable_len);
    print_rc("deserialize_shareable(ctx_b)", rc);
    if (rc != DVCO_CP_OK) {
        print_provider_last_error(api, ctx_b);
        goto done;
    }

    if (api->compare_shareable != NULL) {
        rc = api->compare_shareable(ctx_b, shareable, shareable_len);
        print_cmp_rc("compare_shareable(ctx_b, shareable)", rc);
        if (rc != DVCO_CP_OK) {
            fprintf(stderr, "compare_shareable failed after deserialize_shareable\n");
            print_provider_last_error(api, ctx_b);
            goto done;
        }

        rc = api->compare_shareable(ctx_a, shareable, shareable_len);
        print_cmp_rc("compare_shareable(ctx_a, shareable)", rc);
        if (rc != DVCO_CP_OK) {
            fprintf(stderr, "compare_shareable failed against original ctx_a\n");
            print_provider_last_error(api, ctx_a);
            goto done;
        }
    }

    if (api->serialize_private != NULL) {
        rc = alloc_via_provider_2call(api->serialize_private, ctx_a, &private_blob, &private_blob_len);
        print_rc("serialize_private(ctx_a)", rc);
        if (rc == DVCO_CP_OK) {
            dump_hex("private", private_blob, private_blob_len);
        } else if (rc != DVCO_CP_ERR_NOT_SUPPORTED) {
            print_provider_last_error(api, ctx_a);
            goto done;
        }
    }

    if ((api->deserialize_private != NULL) && (private_blob != NULL)) {
        rc = api->create(kv.items, kv.count, &ctx_c);
        print_rc("create(ctx_c)", rc);
        if (rc != DVCO_CP_OK || ctx_c == NULL) {
            print_provider_last_error(api, ctx_c);
            goto done;
        }

        rc = api->deserialize_private(ctx_c, private_blob, private_blob_len);
        print_rc("deserialize_private(ctx_c)", rc);
        if (rc != DVCO_CP_OK) {
            print_provider_last_error(api, ctx_c);
            goto done;
        }

        if (api->compare_private != NULL) {
            rc = api->compare_private(ctx_c, private_blob, private_blob_len);
            print_cmp_rc("compare_private(ctx_c, private_blob)", rc);
            if (rc != DVCO_CP_OK) {
                fprintf(stderr, "compare_private failed after deserialize_private\n");
                print_provider_last_error(api, ctx_c);
                goto done;
            }

            rc = api->compare_private(ctx_a, private_blob, private_blob_len);
            print_cmp_rc("compare_private(ctx_a, private_blob)", rc);
            if (rc != DVCO_CP_OK) {
                fprintf(stderr, "compare_private failed against original ctx_a\n");
                print_provider_last_error(api, ctx_a);
                goto done;
            }
        }
    }

    rc = alloc_decrypt_2call(api, ctx_b, ciphertext, ciphertext_len, &plaintext_out, &plaintext_out_len);
    print_rc("decrypt(ctx_b)", rc);
    if (rc != DVCO_CP_OK) {
        print_provider_last_error(api, ctx_b);
        goto done;
    }

    dump_hex("decrypted_raw", plaintext_out, plaintext_out_len);

    rc = alloc_unpad_if_needed(&info, plaintext_out, plaintext_out_len, &plaintext_cmp, &plaintext_cmp_len);
    print_rc("normalize_decrypted", rc);
    if (rc != DVCO_CP_OK) {
        goto done;
    }

    printf("decrypted: \"%.*s\" (%zu bytes)\n",
           (int)plaintext_cmp_len,
           (const char *)plaintext_cmp,
           plaintext_cmp_len);

    if (plaintext_cmp_len != plain_len || memcmp(plaintext_cmp, plain_bytes, plain_len) != 0) {
        fprintf(stderr, "Roundtrip mismatch: decrypted payload differs from input\n");
        goto done;
    }

    printf("[PASS] Provider interface exercised successfully.\n");
    exit_code = 0;

done:
    secure_zero_free(encrypt_input, encrypt_input_len);
    secure_zero_free(plaintext_cmp, plaintext_cmp_len);

    free(shareable);
    free(private_blob);
    free(ciphertext);
    free(plaintext_out);

    if (api != NULL && ctx_a != NULL && api->destroy != NULL) {
        api->destroy(ctx_a);
    }
    if (api != NULL && ctx_b != NULL && api->destroy != NULL) {
        api->destroy(ctx_b);
    }
    if (api != NULL && ctx_c != NULL && api->destroy != NULL) {
        api->destroy(ctx_c);
    }
    if (dl_handle != NULL) {
        dlclose(dl_handle);
    }

    free_kv_list(&kv);
    return exit_code;
}


// SPDX-FileCopyrightText: 2026 Daniel Grazioli (graz)
// SPDX-FileCopyrightText: 2026 Ecosteer srl
// SPDX-License-Identifier: MIT

/*
    vector_cipher_provider.c
    Minimal deterministic provider-vector tool.

    Purpose
    -------
    Load one CRAG cipher provider, create an encryption context from the
    supplied confstring, encrypt the supplied plaintext, serialize the
    shareable blob, import it into a second context, and decrypt the ciphertext.

    Important
    ---------
    This tool intentionally does not call reset() or rotate().
    The caller-provided confstring is the source of truth for the key.
 */

#include "ciphers/cipher_provider.h"
#include "padding/dvco_padding.h"

#include <ctype.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static const char g_b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *b64_encode(const uint8_t *data, size_t len)
{
    char *out;
    size_t out_len;
    size_t i;
    size_t j;

    if(data == NULL && len > 0u) {
        return NULL;
    }

    if(len > ((SIZE_MAX / 4u) * 3u)) {
        return NULL;
    }

    out_len = 4u * ((len + 2u) / 3u);
    out = (char *)malloc(out_len + 1u);
    if(out == NULL) {
        return NULL;
    }

    i = 0u;
    j = 0u;
    while(i < len) {
        uint32_t octet_a = i < len ? data[i++] : 0u;
        uint32_t octet_b = i < len ? data[i++] : 0u;
        uint32_t octet_c = i < len ? data[i++] : 0u;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out[j++] = g_b64_table[(triple >> 18) & 0x3Fu];
        out[j++] = g_b64_table[(triple >> 12) & 0x3Fu];
        out[j++] = g_b64_table[(triple >> 6) & 0x3Fu];
        out[j++] = g_b64_table[triple & 0x3Fu];
    }

    if((len % 3u) == 1u) {
        out[out_len - 1u] = '=';
        out[out_len - 2u] = '=';
    } else if((len % 3u) == 2u) {
        out[out_len - 1u] = '=';
    }

    out[out_len] = '\0';
    return out;
}

static void secure_zero_free(uint8_t *p, size_t n)
{
    if(p != NULL) {
        if(n > 0u) {
            memset(p, 0, n);
        }
        free(p);
    }
}

static void usage(const char *prog)
{
    fprintf
    (
        stderr,
        "Usage:\n"
        "  %s --lib <provider.so> --confstring \"k1=v1;k2=v2\" --plain <text>\n"
        "\n"
        "Example:\n"
        "  %s --lib ../../build/debug/lib/libaes_gcm_provider.so \\\n"
        "     --confstring \"keybits=128;key=0x00112233445566778899AABBCCDDEEFF\" \\\n"
        "     --plain \"hello dvco running on psoc\"\n",
        prog,
        prog
    );
}

static int parse_args(int argc, char **argv, app_cfg_t *cfg)
{
    int i;

    if(cfg == NULL) {
        return -1;
    }

    memset(cfg, 0, sizeof(*cfg));
    cfg->plain = "hello dvco";
    cfg->confstring = "";

    for(i = 1; i < argc; i++) {
        if(strcmp(argv[i], "--lib") == 0 && (i + 1) < argc) {
            cfg->lib_path = argv[++i];
        } else if(strcmp(argv[i], "--confstring") == 0 && (i + 1) < argc) {
            cfg->confstring = argv[++i];
        } else if(strcmp(argv[i], "--plain") == 0 && (i + 1) < argc) {
            cfg->plain = argv[++i];
        } else if(strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 1;
        } else {
            fprintf(stderr, "Unknown or incomplete argument: %s\n", argv[i]);
            usage(argv[0]);
            return -1;
        }
    }

    if(cfg->lib_path == NULL) {
        fprintf(stderr, "Missing required --lib argument\n");
        usage(argv[0]);
        return -1;
    }

    return 0;
}

static char *trim_inplace(char *s)
{
    char *end;

    if(s == NULL) {
        return NULL;
    }

    while(*s != '\0' && isspace((unsigned char)*s)) {
        s++;
    }

    if(*s == '\0') {
        return s;
    }

    end = s + strlen(s) - 1u;
    while(end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    return s;
}

static void free_kv_list(kv_list_t *kv)
{
    if(kv == NULL) {
        return;
    }

    free(kv->items);
    free(kv->storage);

    kv->items = NULL;
    kv->storage = NULL;
    kv->count = 0u;
}

static int parse_confstring(const char *confstring, kv_list_t *out_kv)
{
    size_t i;
    size_t pairs_max;
    char *cursor;

    if(out_kv == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    memset(out_kv, 0, sizeof(*out_kv));

    if(confstring == NULL || confstring[0] == '\0') {
        return DVCO_CP_OK;
    }

    pairs_max = 1u;
    for(i = 0u; confstring[i] != '\0'; i++) {
        if(confstring[i] == ';') {
            pairs_max++;
        }
    }

    out_kv->storage = (char *)malloc(strlen(confstring) + 1u);
    if(out_kv->storage == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }
    strcpy(out_kv->storage, confstring);

    out_kv->items = (dvco_kv_t *)calloc(pairs_max, sizeof(dvco_kv_t));
    if(out_kv->items == NULL) {
        free_kv_list(out_kv);
        return DVCO_CP_ERR_ALLOC;
    }

    cursor = out_kv->storage;
    while(cursor != NULL && *cursor != '\0') {
        char *sep;
        char *segment;
        char *eq;
        char *key;
        char *value;

        sep = strchr(cursor, ';');
        if(sep != NULL) {
            *sep = '\0';
            segment = cursor;
            cursor = sep + 1;
        } else {
            segment = cursor;
            cursor = NULL;
        }

        segment = trim_inplace(segment);
        if(*segment == '\0') {
            continue;
        }

        eq = strchr(segment, '=');
        if(eq == NULL) {
            free_kv_list(out_kv);
            return DVCO_CP_ERR_PARSE;
        }

        *eq = '\0';
        key = trim_inplace(segment);
        value = trim_inplace(eq + 1);

        if(*key == '\0') {
            free_kv_list(out_kv);
            return DVCO_CP_ERR_PARSE;
        }

        out_kv->items[out_kv->count].key = key;
        out_kv->items[out_kv->count].value = value;
        out_kv->count++;
    }

    return DVCO_CP_OK;
}

static void dump_hex(const char *label, const uint8_t *p, size_t n)
{
    size_t i;

    printf("%s (%zu bytes): ", label, n);
    for(i = 0u; i < n; i++) {
        printf("%02X", p[i]);
        if(i + 1u < n) {
            printf(" ");
        }
    }
    printf("\n");
}

static void dump_b64(const char *label, const uint8_t *p, size_t n)
{
    char *s;

    s = b64_encode(p, n);
    if(s == NULL) {
        printf("%s_b64: <encode failed>\n", label);
        return;
    }

    printf("%s_b64: %s\n", label, s);
    free(s);
}

static void print_rc(const char *what, int rc)
{
    printf("%s: rc=%d\n", what, rc);
}

static void print_provider_last_error(const dvco_cipher_provider_api_t *api, dvco_cipher_ctx_t *ctx)
{
    const char *s;

    if(api == NULL || api->last_error == NULL) {
        return;
    }

    s = api->last_error(ctx);
    if(s != NULL && s[0] != '\0') {
        printf("provider last_error: %s\n", s);
    }
}

static int alloc_via_provider_2call
(
    int (*fn)(dvco_cipher_ctx_t *, dvco_buf_t *),
    dvco_cipher_ctx_t *ctx,
    uint8_t **out_buf,
    size_t *out_len
)
{
    dvco_buf_t b;
    int rc;

    if(fn == NULL || ctx == NULL || out_buf == NULL || out_len == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_buf = NULL;
    *out_len = 0u;

    b.data = NULL;
    b.len = 0u;
    b.cap = 0u;

    rc = fn(ctx, &b);
    if(rc != DVCO_CP_OK) {
        return rc;
    }

    if(b.len == 0u) {
        return DVCO_CP_ERR_GENERIC;
    }

    b.data = (uint8_t *)malloc(b.len);
    if(b.data == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }
    b.cap = b.len;

    rc = fn(ctx, &b);
    if(rc != DVCO_CP_OK) {
        free(b.data);
        return rc;
    }

    *out_buf = b.data;
    *out_len = b.len;
    return DVCO_CP_OK;
}

static int alloc_encrypt_2call
(
    const dvco_cipher_provider_api_t *api,
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    uint8_t **out_buf,
    size_t *out_len
)
{
    dvco_buf_t b;
    int rc;

    if(api == NULL || api->encrypt == NULL || ctx == NULL || out_buf == NULL || out_len == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_buf = NULL;
    *out_len = 0u;

    b.data = NULL;
    b.len = 0u;
    b.cap = 0u;

    rc = api->encrypt(ctx, in_data, in_len, NULL, 0u, &b);
    if(rc != DVCO_CP_OK) {
        return rc;
    }

    if(b.len == 0u) {
        return DVCO_CP_ERR_GENERIC;
    }

    b.data = (uint8_t *)malloc(b.len);
    if(b.data == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }
    b.cap = b.len;

    rc = api->encrypt(ctx, in_data, in_len, NULL, 0u, &b);
    if(rc != DVCO_CP_OK) {
        free(b.data);
        return rc;
    }

    *out_buf = b.data;
    *out_len = b.len;
    return DVCO_CP_OK;
}

static int alloc_decrypt_2call
(
    const dvco_cipher_provider_api_t *api,
    dvco_cipher_ctx_t *ctx,
    const uint8_t *in_data,
    size_t in_len,
    uint8_t **out_buf,
    size_t *out_len
)
{
    dvco_buf_t b;
    int rc;

    if(api == NULL || api->decrypt == NULL || ctx == NULL || out_buf == NULL || out_len == NULL) {
        return DVCO_CP_ERR_INVALID_ARG;
    }

    *out_buf = NULL;
    *out_len = 0u;

    b.data = NULL;
    b.len = 0u;
    b.cap = 0u;

    rc = api->decrypt(ctx, in_data, in_len, NULL, 0u, &b);
    if(rc != DVCO_CP_OK) {
        return rc;
    }

    if(b.len == 0u) {
        return DVCO_CP_ERR_GENERIC;
    }

    b.data = (uint8_t *)malloc(b.len);
    if(b.data == NULL) {
        return DVCO_CP_ERR_ALLOC;
    }
    b.cap = b.len;

    rc = api->decrypt(ctx, in_data, in_len, NULL, 0u, &b);
    if(rc != DVCO_CP_OK) {
        free(b.data);
        return rc;
    }

    *out_buf = b.data;
    *out_len = b.len;
    return DVCO_CP_OK;
}

static int run_vector
(
    const dvco_cipher_provider_api_t *api,
    const dvco_cipher_provider_info_t *info,
    const kv_list_t *kv,
    const uint8_t *plain,
    size_t plain_len,
    const char *plain_text
)
{
    dvco_cipher_ctx_t *ctx_enc = NULL;
    dvco_cipher_ctx_t *ctx_dec = NULL;

    uint8_t *cipher_input = NULL;
    size_t cipher_input_len = 0u;

    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0u;

    uint8_t *shareable = NULL;
    size_t shareable_len = 0u;

    uint8_t *decrypted = NULL;
    size_t decrypted_len = 0u;
    size_t decrypted_final_len = 0u;

    int rc;
    int result = 1;

    if(api == NULL || info == NULL || kv == NULL || plain == NULL)
    {
        return 1;
    }

    rc = api->create(kv->items, kv->count, &ctx_enc);
    print_rc("create(ctx_enc)", rc);
    if(rc != DVCO_CP_OK || ctx_enc == NULL)
    {
        print_provider_last_error(api, ctx_enc);
        goto done;
    }

    printf("plaintext: \"%s\" (%zu bytes)\n", plain_text, plain_len);
    dump_hex("plain", plain, plain_len);
    dump_b64("plain", plain, plain_len);

    if(info->pad_apply)
    {
        int pad_rc;
        size_t block_size;
        size_t cipher_input_cap;

        block_size = (size_t)info->pad_block_size;

        if(block_size == 0u)
        {
            fprintf(stderr, "Provider requested padding with pad_block_size=0\n");
            goto done;
        }

        if(plain_len > (SIZE_MAX - block_size))
        {
            fprintf(stderr, "Plaintext too large for padding calculation\n");
            goto done;
        }

        cipher_input_cap = plain_len + block_size;

        cipher_input = (uint8_t *)malloc(cipher_input_cap);
        if(cipher_input == NULL)
        {
            fprintf(stderr, "Failed to allocate padded plaintext buffer\n");
            goto done;
        }

        cipher_input_len = cipher_input_cap;

        pad_rc = dvco_pkcs7_pad
        (
            plain
        ,   plain_len
        ,   cipher_input
        ,   &cipher_input_len
        ,   block_size
        );

        printf("pad: rc=%d padded_len=%zu\n", pad_rc, cipher_input_len);
        if(pad_rc != DVCO_PAD_OK)
        {
            goto done;
        }

        dump_hex("padded_plain", cipher_input, cipher_input_len);
        dump_b64("padded_plain", cipher_input, cipher_input_len);
    }
    else
    {
        cipher_input = (uint8_t *)malloc(plain_len);
        if(cipher_input == NULL && plain_len > 0u)
        {
            fprintf(stderr, "Failed to allocate plaintext copy buffer\n");
            goto done;
        }

        if(plain_len > 0u)
        {
            memcpy(cipher_input, plain, plain_len);
        }

        cipher_input_len = plain_len;
    }

    rc = alloc_via_provider_2call(api->serialize_shareable, ctx_enc, &shareable, &shareable_len);
    print_rc("serialize_shareable(ctx_enc)", rc);
    if(rc != DVCO_CP_OK)
    {
        print_provider_last_error(api, ctx_enc);
        goto done;
    }

    dump_hex("shareable", shareable, shareable_len);
    dump_b64("shareable", shareable, shareable_len);

    rc = alloc_encrypt_2call(api, ctx_enc, cipher_input, cipher_input_len, &ciphertext, &ciphertext_len);
    print_rc("encrypt(ctx_enc)", rc);
    if(rc != DVCO_CP_OK)
    {
        print_provider_last_error(api, ctx_enc);
        goto done;
    }

    dump_hex("ciphertext", ciphertext, ciphertext_len);
    dump_b64("ciphertext", ciphertext, ciphertext_len);

    rc = api->create(NULL, 0u, &ctx_dec);
    print_rc("create(ctx_dec)", rc);
    if(rc != DVCO_CP_OK || ctx_dec == NULL)
    {
        print_provider_last_error(api, ctx_dec);
        goto done;
    }

    rc = api->deserialize_shareable(ctx_dec, shareable, shareable_len);
    print_rc("deserialize_shareable(ctx_dec)", rc);
    if(rc != DVCO_CP_OK)
    {
        print_provider_last_error(api, ctx_dec);
        goto done;
    }

    rc = alloc_decrypt_2call(api, ctx_dec, ciphertext, ciphertext_len, &decrypted, &decrypted_len);
    print_rc("decrypt(ctx_dec)", rc);
    if(rc != DVCO_CP_OK)
    {
        print_provider_last_error(api, ctx_dec);
        goto done;
    }

    dump_hex("decrypted_raw", decrypted, decrypted_len);
    dump_b64("decrypted_raw", decrypted, decrypted_len);

    decrypted_final_len = decrypted_len;

    if(info->pad_apply)
    {
        int unpad_rc;

        unpad_rc = dvco_pkcs7_unpad
        (
            decrypted
        ,   &decrypted_final_len
        ,   (size_t)info->pad_block_size
        );

        printf("unpad: rc=%d unpadded_len=%zu\n", unpad_rc, decrypted_final_len);
        if(unpad_rc != DVCO_PAD_OK)
        {
            goto done;
        }
    }

    dump_hex("decrypted", decrypted, decrypted_final_len);
    dump_b64("decrypted", decrypted, decrypted_final_len);

    printf
    (
        "decrypted_text: \"%.*s\" (%zu bytes)\n"
    ,   (int)decrypted_final_len
    ,   (const char *)decrypted
    ,   decrypted_final_len
    );

    if(decrypted_final_len != plain_len || memcmp(decrypted, plain, plain_len) != 0)
    {
        fprintf(stderr, "Roundtrip mismatch\n");
        goto done;
    }

    printf("summary.shareable_hex=");
    for(size_t i = 0u; i < shareable_len; i++)
    {
        printf("%02X", shareable[i]);
    }
    printf("\n");

    printf("summary.cipher_input_hex=");
    for(size_t i = 0u; i < cipher_input_len; i++)
    {
        printf("%02X", cipher_input[i]);
    }
    printf("\n");

    printf("summary.ciphertext_hex=");
    for(size_t i = 0u; i < ciphertext_len; i++)
    {
        printf("%02X", ciphertext[i]);
    }
    printf("\n");

    printf("summary.decrypted_raw_hex=");
    for(size_t i = 0u; i < decrypted_len; i++)
    {
        printf("%02X", decrypted[i]);
    }
    printf("\n");

    printf("summary.decrypted_hex=");
    for(size_t i = 0u; i < decrypted_final_len; i++)
    {
        printf("%02X", decrypted[i]);
    }
    printf("\n");

    result = 0;

done:
    secure_zero_free(cipher_input, cipher_input_len);
    free(shareable);
    free(ciphertext);
    secure_zero_free(decrypted, decrypted_len);

    if(api != NULL && ctx_enc != NULL && api->destroy != NULL)
    {
        api->destroy(ctx_enc);
    }

    if(api != NULL && ctx_dec != NULL && api->destroy != NULL)
    {
        api->destroy(ctx_dec);
    }

    return result;
}



int main(int argc, char **argv)
{
    app_cfg_t cfg;
    kv_list_t kv = {0};
    void *dl_handle = NULL;
    dvco_cipher_provider_get_api_fn get_api_fn = NULL;
    const dvco_cipher_provider_api_t *api = NULL;
    dvco_cipher_provider_info_t info;
    const uint8_t *plain_bytes;
    size_t plain_len;
    int rc;
    int exit_code = 1;

    memset(&info, 0, sizeof(info));

    rc = parse_args(argc, argv, &cfg);
    if(rc != 0) {
        return (rc > 0) ? 0 : 1;
    }

    rc = parse_confstring(cfg.confstring, &kv);
    print_rc("parse_confstring", rc);
    if(rc != DVCO_CP_OK) {
        fprintf(stderr, "Invalid confstring: %s\n", cfg.confstring ? cfg.confstring : "(null)");
        goto done;
    }

    plain_bytes = (const uint8_t *)cfg.plain;
    plain_len = strlen(cfg.plain);

    printf("Loading provider: %s\n", cfg.lib_path);

    dl_handle = dlopen(cfg.lib_path, RTLD_NOW);
    if(dl_handle == NULL) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        goto done;
    }

    get_api_fn = (dvco_cipher_provider_get_api_fn)dlsym(dl_handle, DVCO_CIPHER_PROVIDER_GET_API_SYMBOL);
    if(get_api_fn == NULL) {
        fprintf(stderr, "dlsym failed for symbol %s: %s\n", DVCO_CIPHER_PROVIDER_GET_API_SYMBOL, dlerror());
        goto done;
    }

    rc = get_api_fn(&api);
    print_rc("dvco_cipher_provider_get_api", rc);
    if(rc != DVCO_CP_OK || api == NULL) {
        goto done;
    }

    if(api->get_info == NULL ||
       api->create == NULL ||
       api->destroy == NULL ||
       api->serialize_shareable == NULL ||
       api->deserialize_shareable == NULL ||
       api->encrypt == NULL ||
       api->decrypt == NULL ||
       api->last_error == NULL) {
        fprintf(stderr, "Provider API is incomplete for vector test\n");
        goto done;
    }

    rc = api->get_info(&info);
    print_rc("get_info", rc);
    if(rc != DVCO_CP_OK) {
        goto done;
    }

    printf("Provider info:\n");
    printf("  abi            : %u.%u\n", info.abi_major, info.abi_minor);
    printf("  name           : %s\n", info.provider_name ? info.provider_name : "(null)");
    printf("  version        : %s\n", info.provider_version ? info.provider_version : "(null)");
    printf("  cid            : %u\n", (unsigned)info.cid);
    printf("  pad_apply      : %s\n", info.pad_apply ? "true" : "false");
    printf("  pad_block_size : %zu\n", info.pad_block_size);

    exit_code = run_vector(api, &info, &kv, plain_bytes, plain_len, cfg.plain);
    if(exit_code == 0) {
        printf("[PASS] Vector provider test completed successfully.\n");
    }

done:
    if(dl_handle != NULL) {
        dlclose(dl_handle);
    }
    free_kv_list(&kv);
    return exit_code;
}

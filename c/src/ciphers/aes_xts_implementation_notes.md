# AES-XTS provider implementation notes

Provider identity:

- provider name: aes-xts
- cid: 8
- source: src/ciphers/aes_xts_provider.c
- library: libaes_xts_provider.so
- provider version: 1.0
- provider description: DVCO AES-XTS cipher provider

Configuration:

- xtsbits=128|256, optional, default=256
- key=0x..., optional, fixed initial XTS key

Key semantics:

- xtsbits=128 selects EVP_aes_128_xts() and requires a 32-byte total XTS key
- xtsbits=256 selects EVP_aes_256_xts() and requires a 64-byte total XTS key
- AES-192-XTS is intentionally not supported
- 16-byte, 24-byte, and 48-byte serialized keys are rejected

Lifecycle:

- create() validates configuration and optionally installs a fixed key
- if key is omitted, the provider remains inactive until rotate()
- rotate() is config-free and generates a fresh key using the configured local xtsbits preference
- reset() clears diagnostics only, matching the current AES-family provider style
- deserialize_shareable() installs the effective decrypt state carried by the shareable blob
- deserialize_shareable() does not overwrite the local pref_key_len used by rotate()

Serialization:

- shareable/private format: [key_len_be:2][key:key_len]
- key_len=32 means AES-128-XTS
- key_len=64 means AES-256-XTS
- serialize_private(), deserialize_private(), and compare_private() reuse the shareable implementation

Ciphertext frame:

- frame format: [tweak_len:1][tweak:16][ciphertext]
- tweak_len must be 16
- tweak is generated randomly per encrypt()
- the tweak is not secret and is carried in the provider-owned opaque ciphertext frame

Cryptographic semantics:

- AES-XTS is not AEAD
- no AAD is supported
- no authentication tag is produced or checked
- no DVCO-side padding is applied
- plaintext shorter than 16 bytes is rejected because AES-XTS operates on data units of at least one AES block
- this provider is suitable as a framework stress-test and possible static/block-oriented data provider, not as the default DVCO stream AEAD provider

Build/test:

```sh
make clean_debug
make debug
./src/tools/test_aes_xts.sh
```

Expected standalone behavior:

- provider loads through dlopen
- dvco_cipher_provider_get_api resolves
- get_info reports cid=8
- create/reset/rotate succeed
- encrypt succeeds
- serialize_shareable succeeds
- deserialize_shareable succeeds
- compare_shareable matches
- serialize_private / deserialize_private succeeds
- compare_private matches
- decrypt restores the original plaintext
- test ends with [PASS]

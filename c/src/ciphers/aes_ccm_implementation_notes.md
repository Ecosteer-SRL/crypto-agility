# AES-CCM provider implementation notes

Provider identity:

```text
provider_name    = aes-ccm
provider_version = 1.0
provider_desc    = DVCO AES-CCM cipher provider
cid              = 7
pad_apply        = false
pad_block_size   = 1
```

Configuration:

```c
// conf:
//   keybits=128|192|256          optional, default=256
//   key=0x...                    optional, fixed initial key, must match keybits
//
// rules:
//   - unsupported keys => error
//   - if key is omitted, rotate() must generate the runtime key
//   - nonce is generated internally per encrypt()
//   - AAD not supported
```

Provider-owned ciphertext frame:

```text
[nonce_len:1][nonce:12][ciphertext][tag:16]
```

Shareable/private serialization:

```text
[key_len_be:2][key:key_len]
```

Subscriber-side deserialization installs the effective decrypt state from the shareable blob. The local `pref_key_len` remains only a rotate() preference and is not overwritten by `deserialize_shareable()`.

OpenSSL EVP CCM care point:

AES-CCM is not initialized like AES-GCM. The provider must declare the plaintext/ciphertext length before processing payload bytes:

```c
EVP_EncryptUpdate(evp, NULL, &tmp_len, NULL, (int)in_len);
EVP_DecryptUpdate(evp, NULL, &tmp_len, NULL, (int)ct_len);
```

The authentication tag is configured before key/nonce setup on decrypt and generated after encryption on encrypt.

Build/test:

```sh
make clean_debug
make debug
./src/tools/test_aes_ccm.sh
```

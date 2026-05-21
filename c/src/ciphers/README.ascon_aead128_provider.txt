DVCO Ascon-AEAD128 Provider Notes
=================================

Provider
--------
Name: ascon-aead128
CID: 6
Algorithm: Ascon-AEAD128
Standard: NIST SP 800-232
Core implementation: vendored ascon/ascon-c crypto_aead/asconaead128/ref
Core license: CC0-1.0
Provider wrapper license: MIT / Ecosteer source header

Expected external core location
-------------------------------
src/ciphers/externals/ascon/asconaead128_ref/

Required core sources in Makefile
---------------------------------
externals/ascon/asconaead128_ref/aead.c
externals/ascon/asconaead128_ref/printstate.c

Provider source
---------------
src/ciphers/ascon_aead128_provider.c

Build output
------------
build/<CFG>/lib/libascon_aead128_provider.so

Configuration
-------------
key=0x... optional fixed initial key, exactly 16 bytes.

If key is omitted, the provider starts inactive and rotate() generates a fresh 128-bit key.

Serialization
-------------
shareable/private blob:
[key_len_be:2][key:key_len]

For Ascon-AEAD128 key_len is always 16.

Ciphertext framing
------------------
[nonce_len:1][nonce:16][ciphertext][tag:16]

AAD
---
AAD is not supported in v1. encrypt/decrypt return DVCO_CP_ERR_NOT_SUPPORTED if aad != NULL or aad_len != 0.

Care points
-----------
- Ascon-AEAD128 has a fixed 128-bit key.
- This is not a big-key cipher; its value is modern NIST lightweight AEAD suitability.
- Nonce must be unique per key; provider generates a random 16-byte nonce per encrypt().
- The provider keeps nonce/tag as provider-owned opaque framing details.
- Decrypt fails if authentication/tag verification fails.

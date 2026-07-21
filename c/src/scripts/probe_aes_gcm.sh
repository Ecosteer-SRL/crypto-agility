#!/bin/sh

PROGFOLDER="../../build/debug/bin"
CIPHERFOLDER="../../build/debug/lib"

${PROGFOLDER}/probe_cipher_provider \
--lib ${CIPHERFOLDER}/libaes_gcm_provider.so \
--confstring "keybits=128;key=0x00112233445566778899AABBCCDDEEFF;iv=0x000102030405060708090A0B" \
--plain "hello dvco running on psoc" \
--aad "aadangraz"

# AES-GCM 128-bit key and fixed 12-byte IV for deterministic probing

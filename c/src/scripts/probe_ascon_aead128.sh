#!/bin/sh

PROGFOLDER="../../build/debug/bin"
CIPHERFOLDER="../../build/debug/lib"

${PROGFOLDER}/probe_cipher_provider \
--lib ${CIPHERFOLDER}/libascon_aead128_provider.so \
--confstring "key=0x00112233445566778899AABBCCDDEEFF" \
--plain "hello dvco running on psoc" \
--aad "aadangraz"


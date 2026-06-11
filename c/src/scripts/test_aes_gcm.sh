#!/bin/sh

PROGFOLDER="../../build/debug/bin"
CIPHERFOLDER="../../build/debug/lib"
${PROGFOLDER}/test_cipher_provider \
--lib ${CIPHERFOLDER}/libaes_gcm_provider.so \
--confstring "keybits=128;key=0x00112233445566778899AABBCCDDEEFF" \
--plain "hello dvco running on psoc"
#keybits (use 128, 192 or 256)

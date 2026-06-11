#!/bin/sh

PROGFOLDER="../../build/debug/bin"
CIPHERFOLDER="../../build/debug/lib"
${PROGFOLDER}/test_cipher_provider \
--lib ${CIPHERFOLDER}/libaes_cbc_provider.so \
--confstring "keybits=256" \
--plain "hello dvco"
#keybits (use 128, 192 or 256)


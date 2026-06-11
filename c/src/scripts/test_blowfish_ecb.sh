#!/bin/sh

PROGFOLDER="../../build/debug/bin"
CIPHERFOLDER="../../build/debug/lib"
${PROGFOLDER}/test_cipher_provider \
--lib ${CIPHERFOLDER}/libblowfish_ecb_provider.so \
--confstring "keybits=384" \
--plain "hello dvco"


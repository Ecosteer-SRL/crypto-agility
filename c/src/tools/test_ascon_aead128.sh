#!/bin/sh

PROGFOLDER="../../build/debug/bin"
CIPHERFOLDER="../../build/debug/lib"
${PROGFOLDER}/test_cipher_provider \
--lib ${CIPHERFOLDER}/libascon_aead128_provider.so \
--confstring "" \
--plain "hello dvco"

# optional fixed key example:
# --confstring "key=0x000102030405060708090a0b0c0d0e0f"

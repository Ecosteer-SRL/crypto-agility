#!/bin/sh

PROGFOLDER="../../build/debug/bin"
CIPHERFOLDER="../../build/debug/lib"

${PROGFOLDER}/test_cipher_provider \
--lib ${CIPHERFOLDER}/libaes_ccm_provider.so \
--confstring "" \
--plain "hello dvco"

# optional fixed key example:
# --confstring "keybits=256;key=0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

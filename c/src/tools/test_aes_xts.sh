#!/bin/sh

PROGFOLDER="../../build/debug/bin"
CIPHERFOLDER="../../build/debug/lib"

${PROGFOLDER}/test_cipher_provider \
--lib ${CIPHERFOLDER}/libaes_xts_provider.so \
--confstring "" \
--plain "hello dvco aes xts standalone"

# optional AES-128-XTS fixed key example:
# --confstring "xtsbits=128;key=0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

# optional AES-256-XTS fixed key example:
# --confstring "xtsbits=256;key=0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"

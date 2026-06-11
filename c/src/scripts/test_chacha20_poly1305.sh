#!/bin/sh

PROGFOLDER="../../build/debug/bin"
CIPHERFOLDER="../../build/debug/lib"
${PROGFOLDER}/test_cipher_provider \
--lib ${CIPHERFOLDER}/libchacha20_poly1305_provider.so \
--plain "hello dvco"



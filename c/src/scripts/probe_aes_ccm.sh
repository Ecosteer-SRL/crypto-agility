#!/bin/sh

PROGFOLDER="../../build/debug/bin"
CIPHERFOLDER="../../build/debug/lib"

${PROGFOLDER}/probe_cipher_provider \
--lib ${CIPHERFOLDER}/libaes_ccm_provider.so \
--confstring "keybits=128;key=0x00112233445566778899AABBCCDDEEFF" \
--plain "hello dvco running on psoc" \
--aad "aadangraz"



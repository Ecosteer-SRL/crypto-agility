DVCO Ascon Import Notes
======================

Upstream repository:
https://github.com/ascon/ascon-c

Imported source:
GitHub ZIP archive of the main branch.

Imported component:
crypto_aead/asconaead128/ref

Algorithm:
Ascon-AEAD128

Standard:
NIST SP 800-232

Upstream license:
CC0-1.0 Universal

Local destination:
src/ciphers/externals/ascon/asconaead128_ref/

Imported files:
aead.c
api.h
ascon.h
constants.h
crypto_aead.h
permutations.h
printstate.c
printstate.h
round.h
word.h
LICENSE

Optional provenance/test files:
implementors
LWC_AEAD_KAT_128_128.txt

Local modifications:
None.

DVCO wrapper:
src/ciphers/ascon_aead128_provider.c

Notes:
The imported upstream files are vendored as the portable reference
implementation of Ascon-AEAD128. The DVCO provider wrapper implements the
cipher_provider.h ABI and links this implementation into
libascon_aead128_provider.so.

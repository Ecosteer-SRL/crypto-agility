[1 Overview 6](#overview)

[2 Core Concepts 7](#core-concepts)

[2.1 Provider metadata 7](#provider-metadata)

[2.2 Provider instance state 7](#provider-instance-state)

[2.3 Shareable state 7](#shareable-state)

[2.4 Private state 7](#private-state)

[2.5 Provider-owned ciphertext framing
8](#provider-owned-ciphertext-framing)

[3 ABI Versioning and Common Types 8](#abi-versioning-and-common-types)

[3.1 ABI version 8](#abi-version)

[3.2 Return codes 8](#return-codes)

[3.3 Buffer helper 10](#buffer-helper)

[4 Provider Metadata Contract 10](#provider-metadata-contract)

[4.1 Purpose 10](#purpose)

[4.2 When it is called 10](#when-it-is-called)

[4.3 Inputs 10](#inputs)

[4.4 Outputs 10](#outputs)

[4.5 Required semantics 11](#required-semantics)

[4.6 Padding metadata 11](#padding-metadata)

[4.7 Error conditions 11](#error-conditions)

[5 Lifecycle and State Model 11](#lifecycle-and-state-model)

[6 Full Vtable reference (Cipher Provider Interface)
11](#full-vtable-reference-cipher-provider-interface)

[6.1 Get\_info 12](#get_info)

[6.1.1 Signature 12](#signature)

[6.1.2 Purpose 12](#purpose-1)

[6.1.3 Caller responsibilities 12](#caller-responsibilities)

[6.1.4 Provider responsibilities 12](#provider-responsibilities)

[6.1.5 Return values 12](#return-values)

[6.2 Create 12](#create)

[6.2.1 Signature 12](#signature-1)

[6.2.2 Purpose 12](#purpose-2)

[6.2.3 When it is called 12](#when-it-is-called-1)

[6.2.4 Inputs 13](#inputs-1)

[6.2.5 Configuration semantics 13](#configuration-semantics)

[6.2.6 Required success semantics 13](#required-success-semantics)

[6.2.7 Required failure semantics 13](#required-failure-semantics)

[6.2.8 Ownership 13](#ownership)

[6.2.9 Error conditions 14](#error-conditions-1)

[6.3 Destroy 14](#destroy)

[6.3.1 Signature 14](#signature-2)

[6.3.2 Purpose 14](#purpose-3)

[6.3.3 When it is called 14](#when-it-is-called-2)

[6.3.4 Inputs 14](#inputs-2)

[6.3.5 Required semantics 14](#required-semantics-1)

[6.3.6 Ownership 14](#ownership-1)

[6.4 Reset 14](#reset)

[6.4.1 Signature 14](#signature-3)

[6.4.2 Purpose 14](#purpose-4)

[6.4.3 When it is called 15](#when-it-is-called-3)

[6.4.4 Expected semantics 15](#expected-semantics)

[6.4.5 Recommendation 15](#recommendation)

[6.4.6 Error Conditions 15](#error-conditions-2)

[6.5 Rotate 15](#rotate)

[6.5.1 Signature 15](#signature-4)

[6.5.2 Purpose 15](#purpose-5)

[6.5.3 When it is called 15](#when-it-is-called-4)

[6.5.4 Required semantics 15](#required-semantics-2)

[6.5.5 Important design assumption 16](#important-design-assumption)

[6.5.6 Freshness requirement 16](#freshness-requirement)

[6.5.7 Failure semantics 16](#failure-semantics)

[6.5.8 Error conditions 16](#error-conditions-3)

[6.6 Serialize\_shareable 16](#serialize_shareable)

[6.6.1 Signature 16](#signature-5)

[6.6.2 Purpose 17](#purpose-6)

[6.6.3 When it is called 17](#when-it-is-called-5)

[6.6.4 Output semantics 17](#output-semantics)

[6.6.5 State requirements 17](#state-requirements)

[6.6.6 Two-call sizing convention 17](#two-call-sizing-convention)

[6.6.7 Error conditions 17](#error-conditions-4)

[6.7 Deserialize\_shareable 18](#deserialize_shareable)

[6.7.1 Signature 18](#signature-6)

[6.7.2 Purpose 18](#purpose-7)

[6.7.3 When it is called 18](#when-it-is-called-6)

[6.7.4 Required semantics 18](#required-semantics-3)

[6.7.5 Blob format 18](#blob-format)

[6.7.6 Local configuration preservation
18](#local-configuration-preservation)

[6.7.7 Error conditions 19](#error-conditions-5)

[6.8 Compare shareable 19](#compare-shareable)

[6.8.1 Signature 19](#signature-7)

[6.8.2 Purpose 19](#purpose-8)

[6.8.3 When it is called 19](#when-it-is-called-7)

[6.8.4 Required semantics 19](#required-semantics-4)

[6.8.5 Recommended mismatch behavior 19](#recommended-mismatch-behavior)

[6.8.6 State requirements 19](#state-requirements-1)

[6.9 Serialize\_private 20](#serialize_private)

[6.9.1 Signature 20](#signature-8)

[6.9.2 Purpose 20](#purpose-9)

[6.9.3 Support level 20](#support-level)

[6.9.4 Semantics 20](#semantics)

[6.9.5 Relationship to shareable 20](#relationship-to-shareable)

[6.10 Deserialize\_private 20](#deserialize_private)

[6.10.1 Signature 20](#signature-9)

[6.10.2 Purpose 21](#purpose-10)

[6.10.3 Support level 21](#support-level-1)

[6.10.4 Required semantics 21](#required-semantics-5)

[6.10.5 Error conditions 21](#error-conditions-6)

[6.11 Compare private 21](#compare-private)

[6.11.1 Signature 21](#signature-10)

[6.11.2 Purpose 21](#purpose-11)

[6.11.3 Support level 21](#support-level-2)

[6.11.4 Required semantics 22](#required-semantics-6)

[6.12 Encrypt 22](#encrypt)

[6.12.1 Signature 22](#signature-11)

[6.12.2 Purpose 22](#purpose-12)

[6.12.3 Inputs 22](#inputs-3)

[6.12.4 State requirements 22](#state-requirements-2)

[6.12.5 Output semantics 22](#output-semantics-1)

[6.12.6 Two-call sizing convention 23](#two-call-sizing-convention-1)

[6.12.7 AAD semantics 23](#aad-semantics)

[6.12.8 Input validation 23](#input-validation)

[6.12.9 Error conditions 23](#error-conditions-7)

[6.13 Decrypt 23](#decrypt)

[6.13.1 Signature 23](#signature-12)

[6.13.2 Purpose 24](#purpose-13)

[6.13.3 Inputs 24](#inputs-4)

[6.13.4 Required contract 24](#required-contract)

[6.13.5 Two-call sizing convention 24](#two-call-sizing-convention-2)

[6.13.6 AAD semantics 24](#aad-semantics-1)

[6.13.7 AEAD authentication failures 24](#aead-authentication-failures)

[6.13.8 Error conditions 24](#error-conditions-8)

[6.14 Last\_error 25](#last_error)

[6.14.1 Signature 25](#signature-13)

[6.14.2 Purpose 25](#purpose-14)

[6.14.3 Semantics 25](#semantics-1)

[6.14.4 Optionality 25](#optionality)

[6.14.5 Recommendation 25](#recommendation-1)

[6.14.6 Limitations 25](#limitations)

[7 Buffer and Output Conventions 26](#buffer-and-output-conventions)

[8 Shareable vs Private Semantics 26](#shareable-vs-private-semantics)

[8.1 Shareable means 26](#shareable-means)

[8.2 Private means 26](#private-means)

[8.3 Other considerations 27](#other-considerations)

[8.4 What subscriber install expects
27](#what-subscriber-install-expects)

[8.5 What compare\_\* should verify 27](#what-compare_-should-verify)

[9 Padding Contract 27](#padding-contract)

[9.1 Provider responsibility 28](#provider-responsibility)

[10 Encrypt/Decrypt Contract 28](#encryptdecrypt-contract)

[10.1 Mandatory rule 28](#mandatory-rule)

[10.2 Outer layer assumptions 28](#outer-layer-assumptions)

[10.3 Other considerations 29](#other-considerations-1)

[10.4 AAD behavior 29](#aad-behavior)

[10.5 AEAD behavior 29](#aead-behavior)

[11 Error Model and State Semantics
29](#error-model-and-state-semantics)

[11.1 Invalid argument failures 29](#invalid-argument-failures)

[11.2 Bad state failures 30](#bad-state-failures)

[11.3 Parse failures 30](#parse-failures)

[11.4 Config failures 30](#config-failures)

[11.5 Crypto failures 30](#crypto-failures)

[11.6 Allocation failures 31](#allocation-failures)

[11.7 Feature exists in ABI but not in this provider.
31](#feature-exists-in-abi-but-not-in-this-provider.)

[11.8 last\_error guidance 31](#last_error-guidance)

[12 Plugin Entry Point 31](#plugin-entry-point)

[13 Provider Implementation Checklist
32](#provider-implementation-checklist)

[13.1 Step 1: define provider identity
32](#step-1-define-provider-identity)

[13.2 Step 2: define the provider context
32](#step-2-define-the-provider-context)

[13.3 Step 3: define activation semantics
32](#step-3-define-activation-semantics)

[13.4 Step 4: define shareable format
32](#step-4-define-shareable-format)

[13.5 Step 5: define private format 32](#step-5-define-private-format)

[13.6 Step 6: define ciphertext framing
32](#step-6-define-ciphertext-framing)

[13.7 Step 7: decide AAD policy 33](#step-7-decide-aad-policy)

[13.8 Step 8: decide padding policy 33](#step-8-decide-padding-policy)

[13.9 Step 9: implement two-call sizing correctly
33](#step-9-implement-two-call-sizing-correctly)

[13.10 Step 10: implement robust input validation
33](#step-10-implement-robust-input-validation)

[13.11 Step 11: implement secure cleanup
33](#step-11-implement-secure-cleanup)

[13.12 Step 12: implement useful diagnostics
33](#step-12-implement-useful-diagnostics)

[13.13 Step 13: verify interoperability
33](#step-13-verify-interoperability)

[14 Example Provider Classes 34](#example-provider-classes)

[14.1 Padded block cipher provider 34](#padded-block-cipher-provider)

[14.2 Non-padded stream-like provider
34](#non-padded-stream-like-provider)

[14.3 AEAD provider 34](#aead-provider)

[15 Final Notes for Provider Authors
35](#final-notes-for-provider-authors)

# Overview

This framework was conceived to explore, in practical implementation
terms, one possible way to achieve a high degree of cipher agility in a
live system. Its objective is not merely to abstract cipher calls, but
to enable the runtime replacement, coexistence, rotation, installation,
and long-term evolution of cryptographic providers without requiring
redesign of the surrounding DVCO stack. In this sense, the project can
be read as a pragmatic architectural response to the broader problem of
cryptographic agility.

This direction appears strongly convergent with the perspective later
articulated by NIST in December 2025 in CSWP 39, Considerations for
Achieving Cryptographic Agility: Strategies and Practices. NIST frames
cryptographic agility as the capability to replace and adapt
cryptographic algorithms while preserving security and ongoing
operations. The DVCO cipher provider framework explores one concrete
implementation path toward that goal by isolating cipher-specific logic
behind a stable provider ABI and by enabling provider-defined state
serialization, runtime selection, and rotation within an otherwise
unchanged outer protocol.

More specifically, the DVCO cipher provider framework defines the ABI
used by runtime-loadable cipher plugins for the DVCO publisher and
subscriber stacks. A cipher provider encapsulates all cipher-specific
logic behind a stable vtable so that the outer DVCO protocol and the
pub/proxy/sub flow do not need to be redesigned when introducing a new
cipher.

In practice, the provider framework gives the DVCO stack a concrete
mechanism for cryptographic agility. The outer stack selects a provider
by fixed cid, creates a provider instance, rotates or installs provider
state, and then delegates encryption, decryption, and state
serialization to the provider. The stack treats provider outputs as
opaque except where the ABI explicitly defines common metadata or buffer
conventions.

The provider interface is intentionally broad enough to support multiple
implementation classes, including:

  - padded block ciphers

  - non-padded stream-like ciphers

  - AEAD ciphers

A provider may define its own internal framing for ciphertext, shareable
state, and private state, provided that it respects the common ABI,
lifecycle, and buffer/output conventions documented here.

The framework solves four practical problems:

  - runtime selection of ciphers by **cid**

  - provider-specific state generation and rotation

  - transport of receiver-installable cryptographic state through
    provider-defined serialized blobs

  - decoupling of outer DVCO framing from cipher-specific details such
    as IVs, nonces, tags, and key blob formats

The provider ABI should therefore be understood as a stable developer
contract for implementing new cipher modules.

At the time of writing, the framework has been validated both
conceptually and practically. At the conceptual level, the provider ABI
and vtable have been designed to be sufficiently general-purpose to
support heterogeneous cipher families and provider-specific framing,
serialization, and state-management models without redesign of the outer
stack. At the practical level, this is no longer a purely theoretical
architecture: the provider framework and the associated software have
been implemented, exercised with multiple cipher families, and validated
through end-to-end tests.

A final clarification is important. The purpose of this project is not
to invent or standardize ciphers, but to design and implement a
framework capable of hosting multiple ciphers in a manner that supports
cryptographic agility.

Consequently, the cipher implementations included in this project, even
when functional and end-to-end validated, should be regarded primarily
as instruments for validating the framework. Their purpose is to
demonstrate that the provider model can accommodate heterogeneous cipher
families under a stable ABI and outer protocol, rather than to present
those implementations as authoritative cryptographic artifacts in their
own right.

The project team does not claim to be a team of cryptographers. For this
reason, the implementations provided here are based on existing
specifications, technical documentation, and available open-source code,
and should be read in that context.

# Core Concepts

## Provider metadata

Each provider exports metadata through get\_info(). This metadata
describes:

  - ABI compatibility

  - provider identity and descriptive strings

  - fixed cipher selector **cid**

  - padding expectations exposed to the upper layer

The metadata is static for the provider implementation. In particular,
**cid** is fixed per provider family and is not instance-specific
runtime state.

## Provider instance state

A provider instance is represented by an opaque dvco\_cipher\_ctx\_t
\*ctx.

The context contains all provider-owned runtime states needed to perform
operations such as:

  - encrypt

  - decrypt

  - rotate

  - serialize state

  - deserialize state

  - report errors

The caller must treat **ctx** as opaque and must never inspect or modify
its internals.

## Shareable state

The shareable blob is the serialized provider-defined state that can be
propagated to another stack component so that the receiver can
reconstruct the decryption state required for normal operation.

The exact blob format is provider-defined.

Typical contents may include:

  - key material

  - algorithm parameters

  - mode-specific information

  - any other provider state required by the receiver

The shareable representation should contain what the remote side needs
to reconstruct usable decryption state, excluding local-only information
that must not be propagated.

## Private state

The private blob is the serialized provider-defined local state used for
persistence, recovery, or implementation-defined local workflows.

It is not automatically part of the DVCO wire protocol unless a higher
layer explicitly decides to transport it.

Depending on provider design, the private blob may:

  - be identical to the shareable blob

  - be a strict superset of the shareable blob

  - contain local-only state not suitable for propagation

## Provider-owned ciphertext framing

Ciphertext emitted by encrypt() is provider-defined opaque output.

The outer DVCO stack does not parse provider ciphertext and does not
assume any universal layout. A provider may include internal framing
such as:

  - IV length + IV + ciphertext

  - nonce length + nonce + ciphertext + tag

  - fixed-length nonce prefix

  - algorithm-specific header bytes

The only required contract is that decrypt() must accept exactly the
format emitted by the corresponding encrypt() implementation for that
provider.

# ABI Versioning and Common Types

## ABI version

The framework defines:

  - DVCO\_CIPHER\_PROVIDER\_API\_VERSION\_MAJOR

  - DVCO\_CIPHER\_PROVIDER\_API\_VERSION\_MINOR

A provider must report a compatible ABI version through get\_info().

The general expectation is:

  - major version mismatch means ABI incompatibility

  - minor version may allow backward-compatible evolution depending on
    loader policy

## Return codes

All provider functions return an integer status code using the common
return code set:

  - DVCO\_CP\_OK

  - DVCO\_CP\_ERR\_GENERIC

  - DVCO\_CP\_ERR\_INVALID\_ARG

  - DVCO\_CP\_ERR\_BAD\_STATE

  - DVCO\_CP\_ERR\_NOT\_SUPPORTED

  - DVCO\_CP\_ERR\_ALLOC

  - DVCO\_CP\_ERR\_BUFFER\_TOO\_SMALL

  - DVCO\_CP\_ERR\_PARSE

  - DVCO\_CP\_ERR\_CONFIG

  - DVCO\_CP\_ERR\_CRYPTO

These return codes should be used consistently.

Recommended interpretation:

  - INVALID\_ARG: NULL pointer, inconsistent arguments, malformed caller
    usage

  - BAD\_STATE: provider instance exists but is not in a usable state
    for the requested operation

  - NOT\_SUPPORTED: optional feature not supported by this provider

  - ALLOC: allocation failure

  - BUFFER\_TOO\_SMALL: caller-provided output buffer is insufficient

  - PARSE: blob or ciphertext cannot be parsed as valid provider input

  - CONFIG: configuration error or invalid provider-specific config
    value

  - CRYPTO: cryptographic failure, including authentication failure for
    AEAD providers

  - GENERIC: fallback only when a more specific code is not appropriate

## Buffer helper

Several ABI functions use dvco\_buf\_t:

typedef struct dvco\_buf\_s {

uint8\_t \*data;

size\_t len;

size\_t cap;

} dvco\_buf\_t;

Semantic meaning:

  - **data**: output buffer pointer, or NULL for size query mode

  - **len**: actual output length on success, or required length during
    a size query / too-small condition

  - **cap**: capacity of data

The provider must not write beyond cap.

# Provider Metadata Contract

int (\*get\_info)(dvco\_cipher\_provider\_info\_t \*out\_info);

## Purpose

Returns provider metadata describing ABI compatibility and provider
characteristics.

## When it is called

Typically by the loader during plugin discovery or registration, before
any instance is created.

## Inputs

**out\_info**: caller-allocated output structure

## Outputs

On success, out\_info must be fully initialized with:

  - abi\_major

  - abi\_minor

  - provider\_name

  - provider\_version

  - provider\_desc

  - cid

  - pad\_apply

  - pad\_block\_size

## Required semantics

The provider must return stable metadata for the implementation.

**cid** is the fixed selector identifying the provider family and must
remain consistent with marketplace/domain mapping used by the stack.

## Padding metadata

**pad\_apply** and **pad\_block\_size** define the padding contract
between the provider and the upper layer.

If **pad\_apply == true**, the upper layer is expected to apply padding
using pad\_block\_size before handing plaintext to the provider, and the
overall stack must remain consistent with that choice.

If **pad\_apply == false**, the provider is responsible for operating
directly on the incoming plaintext length without requiring outer-layer
padding.

Important: providers whose underlying crypto library performs internal
mode padding should expose metadata consistent with the actual stack
behavior. The metadata must describe what the upper layer must do, not
merely what the cipher family does in theory.

## Error conditions

DVCO\_CP\_ERR\_INVALID\_ARG if out\_info == NULL

# Lifecycle and State Model

A provider instance typically moves through the following states:

1.  created but inactive

2.  activated by rotate() or deserialize\_shareable() or
    deserialize\_private()

3.  used for encrypt() and/or decrypt()

4.  reset and reused

5.  destroyed

A provider may require explicit activation before use. In that model:

  - **create()** allocates a context but does not yet make it
    cryptographically usable

  - **rotate()** generates fresh active state for publisher-side
    encryption

  - **deserialize\_shareable()** installs receiver-usable state from a
    shareable blob

  - **deserialize\_private()** installs local persisted state

If the provider requires activation before first use, then
**encrypt()**, **decrypt()**, and serialization functions should fail
with DVCO\_CP\_ERR\_BAD\_STATE until valid active state exists.

# Full Vtable reference (Cipher Provider Interface)

## Get\_info

### Signature

int (\*get\_info)(dvco\_cipher\_provider\_info\_t \*out\_info);

### Purpose

Return static provider metadata.

### Caller responsibilities

Allocate out\_info and pass a valid pointer.

### Provider responsibilities

Fully initialize out\_info on success.

### Return values

  - DVCO\_CP\_OK on success

  - DVCO\_CP\_ERR\_INVALID\_ARG if out\_info == NULL

## Create

### Signature

int (\*create)(

const dvco\_kv\_t \*cfg,

size\_t cfg\_count,

dvco\_cipher\_ctx\_t \*\*out\_ctx

);

### Purpose

The **create** instantiates a provider-owned cipher context
(dvco\_cipher\_ctx\_t) from a configuration key/value list
(dvco\_kv\_t\[\]). The returned context is subsequently used with the
provider’s vtable functions (encrypt, decrypt, reset, rotate, etc.) and
must be destroyed via **destroy**.

### When it is called

When the stack needs a new provider instance.

### Inputs

  - cfg: optional array of key/value pairs

  - cfg\_count: number of entries in cfg

  - out\_ctx: output pointer receiving the new context

### Configuration semantics

The outer stack is configuration-format agnostic. It passes
provider-specific key/value pairs but does not interpret them.

The provider may:

  - accept known keys

  - reject invalid values

  - ignore unknown keys

  - reject unknown keys as a hard configuration error

That choice should be documented by the provider.

### Required success semantics

On success, create() must:

  - return DVCO\_CP\_OK

  - set \*out\_ctx to a valid initialized context

The context may still be inactive if the provider requires rotate() or
deserialization before use.

### Required failure semantics

On failure, create() must:

  - > return a non-zero error code

  - > leave \*out\_ctx == NULL

  - > free all partially allocated resources before returning

No partially constructed context may escape on failure.

### Ownership

The returned context is provider-owned opaque memory. The caller owns
only the handle and must eventually call destroy().

### Error conditions

Typical cases:

  - DVCO\_CP\_ERR\_INVALID\_ARG

  - DVCO\_CP\_ERR\_ALLOC

  - DVCO\_CP\_ERR\_CONFIG

## Destroy

### Signature

void (\*destroy)(dvco\_cipher\_ctx\_t \*ctx);

### Purpose

Destroy a provider instance and release all associated resources.

### When it is called

When the caller is done with the context.

### Inputs

  - **ctx**: provider instance or NULL

### Required semantics

The provider must:

  - tolerate NULL

  - release all owned resources

  - wipe sensitive material where applicable before freeing memory

After **destroy(ctx)**, the context is invalid and must not be reused.

### Ownership

After destroy, the caller must consider the handle dead.

## Reset

### Signature

int (\*reset)(dvco\_cipher\_ctx\_t \*ctx);

### Purpose

Reset provider runtime state without destroying the context.

### When it is called

When the stack wants to reuse the instance or clear transient runtime
state.

### Expected semantics

This function is provider-defined but should be conservative and well
documented.

Typical acceptable meanings:

  - clear transient state while keeping long-lived configuration

  - clear error state

  - return instance to a clean inactive state

  - reset internal counters or nonces if such behavior is safe for the
    provider design

The exact post-reset state must be documented by the provider.

### Recommendation

A provider should not use reset() to silently generate new cryptographic
state. That is the role of rotate().

### Error Conditions

  - DVCO\_CP\_ERR\_INVALID\_ARG if ctx == NULL

  - DVCO\_CP\_ERR\_BAD\_STATE if reset is not valid in the current state

## Rotate

\[rotate\]

### Signature

int (\*rotate)(dvco\_cipher\_ctx\_t \*ctx);

### Purpose

Generate and activate fresh provider state for subsequent encryption
operations.

### When it is called

Typically on the publisher side when rotating key/state for the active
stream.

### Required semantics

On success, rotate() must leave the provider in an active and usable
state.

After a successful rotate:

  - encrypt() must be usable

  - serialize\_shareable() must export the new shareable state

  - serialize\_private() must export corresponding private state if
    supported

### Important design assumption

rotate() is config-free after create().

This means all provider configuration affecting rotation should already
be stored in the context during create(). The stack should not need to
pass a second config blob to rotate().

### Freshness requirement

rotate() must activate fresh cryptographic state appropriate for the
provider. Depending on implementation this may include:

  - a new symmetric key

  - fresh seed material

  - provider-specific rotation state

  - any combination of the above

### Failure semantics

On failure, the provider should return a meaningful error and leave the
context in a clearly defined state. Preferred behavior is:

  - do not expose half-generated state

  - either preserve the previously valid active state or transition to a
    clearly inactive state

  - ensure last\_error() reflects the failure when possible

### Error conditions

Typical cases:

  - DVCO\_CP\_ERR\_INVALID\_ARG

  - DVCO\_CP\_ERR\_BAD\_STATE

  - DVCO\_CP\_ERR\_CRYPTO

## Serialize\_shareable

### Signature

int (\*serialize\_shareable)(

dvco\_cipher\_ctx\_t \*ctx,

dvco\_buf\_t \*out

);

### Purpose

Serialize the provider-defined shareable blob.

### When it is called

When the stack needs the transportable representation of the current
provider state.

### Output semantics

The blob format is provider-defined and opaque to the outer stack.

### State requirements

If the provider is not active or does not have serializable shareable
state, this should fail with DVCO\_CP\_ERR\_BAD\_STATE.

### Two-call sizing convention

This function must support the standard two-call pattern:

1.  caller passes out-\>data == NULL

2.  provider returns DVCO\_CP\_OK and sets out-\>len to the required
    size

3.  caller allocates a buffer of at least that size

4.  caller calls again with out-\>data \!= NULL, out-\>cap set

5.  provider writes the blob and sets out-\>len to actual output size

If out-\>cap is too small, the provider must:

set out-\>len to required size

return DVCO\_CP\_ERR\_BUFFER\_TOO\_SMALL

### Error conditions

Typical cases:

  - DVCO\_CP\_ERR\_INVALID\_ARG

  - DVCO\_CP\_ERR\_BAD\_STATE

  - DVCO\_CP\_ERR\_BUFFER\_TOO\_SMALL

## Deserialize\_shareable

### Signature

int (\*deserialize\_shareable)(

dvco\_cipher\_ctx\_t \*ctx,

const uint8\_t \*in\_data,

size\_t in\_len

);

### Purpose

Install provider state from a shareable blob.

### When it is called

Typically on the subscriber side after receiving or looking up the
shareable representation associated with a key installation event.

### Required semantics

On success, the provider must reconstruct a usable state from the input
blob.

After successful deserialize\_shareable(), the context should be ready
for at least:

  - decrypt()

  - compare\_shareable()

  - serialize\_shareable()

Depending on provider design it may also be valid for encrypt().

### Blob format

The blob format is provider-defined. The provider must validate
structure, lengths, and semantic consistency before accepting it.

### Local configuration preservation

When deserializing shareable state, provider implementations should
avoid overwriting unrelated local preferences stored in the context
unless that overwrite is part of the documented provider contract.

### Error conditions

Typical cases:

  - DVCO\_CP\_ERR\_INVALID\_ARG

  - DVCO\_CP\_ERR\_PARSE

  - DVCO\_CP\_ERR\_BAD\_STATE

## Compare shareable

### Signature

int (\*compare\_shareable)(

dvco\_cipher\_ctx\_t \*ctx,

const uint8\_t \*blob,

size\_t blob\_len

);

### Purpose

Check whether a given shareable blob matches the currently installed
provider state.

### When it is called

Useful for validation, duplicate detection, consistency checks, or test
harness verification.

### Required semantics

The provider should:

  - parse and validate the incoming blob

  - compare it against the current installed state

  - return DVCO\_CP\_OK if it matches

  - return a non-OK code if it does not match or cannot be parsed

### Recommended mismatch behavior

Use:

  - DVCO\_CP\_ERR\_PARSE for malformed or structurally inconsistent blob
    input

  - a documented non-OK result for well-formed but non-matching content

If mismatch is represented using PARSE in the current implementation,
document that clearly and keep it consistent.

### State requirements

If no current comparable state is installed, return
DVCO\_CP\_ERR\_BAD\_STATE.

## Serialize\_private

### Signature

int (\*serialize\_private)(

dvco\_cipher\_ctx\_t \*ctx,

dvco\_buf\_t \*out

);

### Purpose

Serialize provider-defined private state for local persistence or
recovery.

### Support level

Optional in v1. A provider may return DVCO\_CP\_ERR\_NOT\_SUPPORTED.

### Semantics

Uses the same dvco\_buf\_t contract and the same two-call sizing
convention as serialize\_shareable().

### Relationship to shareable

The private blob may:

  - equal the shareable blob

  - include local-only state

  - differ entirely in format

This is provider-defined.

## Deserialize\_private

### Signature

int (\*deserialize\_private)(

dvco\_cipher\_ctx\_t \*ctx,

const uint8\_t \*in\_data,

size\_t in\_len

);

### Purpose

Install provider state from a private serialized representation.

### Support level

Optional in v1. A provider may return DVCO\_CP\_ERR\_NOT\_SUPPORTED.

### Required semantics

On success, the context must contain a usable provider state according
to the provider’s documented lifecycle.

### Error conditions

Typical cases:

  - DVCO\_CP\_ERR\_INVALID\_ARG

  - DVCO\_CP\_ERR\_PARSE

  - DVCO\_CP\_ERR\_BAD\_STATE

  - DVCO\_CP\_ERR\_NOT\_SUPPORTED

## Compare private

### Signature

int (\*compare\_private)(

dvco\_cipher\_ctx\_t \*ctx,

const uint8\_t \*blob,

size\_t blob\_len

);

### Purpose

Compare a private blob against currently installed provider state.

### Support level

Optional in v1, consistent with private serialization support.

### Required semantics

Equivalent in spirit to compare\_shareable(), but against the
private-state format.

## Encrypt

### Signature

int (\*encrypt)(

dvco\_cipher\_ctx\_t \*ctx,

const uint8\_t \*in\_data,

size\_t in\_len,

const uint8\_t \*aad,

size\_t aad\_len,

dvco\_buf\_t \*out

);

### Purpose

Encrypt plaintext payload bytes and emit provider-defined opaque
ciphertext output.

### Inputs

  - ctx: active provider context

  - in\_data, in\_len: plaintext

  - aad, aad\_len: optional associated data

  - out: output buffer descriptor

### State requirements

The provider must reject encryption when the context is not in an active
usable state.

### Output semantics

The provider owns the ciphertext framing. It may include internally:

  - IV

  - nonce

  - tag

  - mode-specific header fields

  - any provider-defined per-message cryptographic metadata

The outer layer must treat this output as opaque.

### Two-call sizing convention

encrypt() must support the same two-call sizing pattern as serialization
functions.

If out-\>data == NULL, the provider returns the required size in
out-\>len.

If out-\>cap is too small, the provider sets out-\>len to required size
and returns DVCO\_CP\_ERR\_BUFFER\_TOO\_SMALL.

### AAD semantics

AAD is optional at the ABI level.

A provider may:

  - support AAD and require exact match during decrypt

  - ignore AAD when unused by design

  - reject non-NULL or non-zero AAD input with
    DVCO\_CP\_ERR\_NOT\_SUPPORTED

The provider must document which of these applies.

### Input validation

If in\_len \> 0, then in\_data must not be NULL.

### Error conditions

Typical cases:

  - DVCO\_CP\_ERR\_INVALID\_ARG

  - DVCO\_CP\_ERR\_BAD\_STATE

  - DVCO\_CP\_ERR\_NOT\_SUPPORTED

  - DVCO\_CP\_ERR\_BUFFER\_TOO\_SMALL

  - DVCO\_CP\_ERR\_ALLOC

  - DVCO\_CP\_ERR\_CRYPTO

## Decrypt

### Signature

int (\*decrypt)(

dvco\_cipher\_ctx\_t \*ctx,

const uint8\_t \*in\_data,

size\_t in\_len,

const uint8\_t \*aad,

size\_t aad\_len,

dvco\_buf\_t \*out

);

### Purpose

Decrypt provider-defined opaque ciphertext bytes and emit plaintext
payload.

### Inputs

  - ctx: provider context with installed usable state

  - in\_data, in\_len: provider-defined ciphertext emitted by encrypt()

  - aad, aad\_len: optional associated data if supported

  - out: plaintext output buffer descriptor

### Required contract

decrypt() must accept exactly the format emitted by the corresponding
provider’s encrypt().

The outer stack must not reinterpret or normalize provider ciphertext
before passing it to decrypt().

### Two-call sizing convention

decrypt() should support the same two-call sizing pattern as encrypt()
and serialization functions.

For decryption, the size-query result may be a safe upper bound rather
than an exact final plaintext length if the exact value depends on
successful decryption and validation of input framing or padding. The
provider should document whether the queried size is exact or an upper
bound.

### AAD semantics

If the provider supports AAD, decrypt must validate it consistently with
encrypt semantics.

If the provider does not support AAD, it should reject unsupported AAD
input with DVCO\_CP\_ERR\_NOT\_SUPPORTED.

### AEAD authentication failures

For AEAD providers, authentication or tag verification failure should
return DVCO\_CP\_ERR\_CRYPTO.

The provider should not output plaintext on authentication failure.

### Error conditions

Typical cases:

  - DVCO\_CP\_ERR\_INVALID\_ARG

  - DVCO\_CP\_ERR\_BAD\_STATE

  - DVCO\_CP\_ERR\_NOT\_SUPPORTED

  - DVCO\_CP\_ERR\_BUFFER\_TOO\_SMALL

  - DVCO\_CP\_ERR\_PARSE

  - DVCO\_CP\_ERR\_CRYPTO

Use PARSE when the ciphertext framing itself is malformed.

Use CRYPTO when cryptographic verification or decryption fails after
successful parsing.

## Last\_error

### Signature

const char \*(\*last\_error)(dvco\_cipher\_ctx\_t \*ctx);

### Purpose

Return the most recent provider-specific diagnostic string for the given
context.

### Semantics

The returned pointer is provider-owned and must be treated as read-only.

The caller must not free it.

The string may be overwritten by later provider operations.

### Optionality

This function may return NULL.

### Recommendation

Providers should update the last-error string whenever returning a
meaningful non-OK status after a context exists.

### Limitations

last\_error(ctx) only works when a context exists. It cannot solve
diagnostics for create() failures that occur before a context is
returned unless the provider implements an additional out-of-band
mechanism.

# Buffer and Output Conventions

The following functions must support the standard two-call sizing
pattern:

  - serialize\_shareable

  - serialize\_private

  - encrypt

  - decrypt

Recommended caller pattern:

1.  initialize dvco\_buf\_t out = {0}

2.  set out.data = NULL

3.  call function to obtain out.len

4.  allocate out.data with capacity at least out.len

5.  set out.cap

6.  call function again

Provider obligations:

  - if out-\>data == NULL, return required size in out-\>len

  - if out-\>data \!= NULL and out-\>cap \< required, set out-\>len =
    required and return DVCO\_CP\_ERR\_BUFFER\_TOO\_SMALL

  - on success, set out-\>len to actual bytes written

A provider must never write partial output beyond the valid range or
beyond out-\>cap.

# Shareable vs Private Semantics

Provider authors must document clearly what their two serialization
families mean.

## Shareable means

The serialized state that may be propagated to another DVCO component so
that the receiver can reconstruct usable cryptographic state.

Typical use cases:

  - publisher to proxy or subscriber key propagation

  - subscriber install path

  - OOB / GETIDX retrieval workflows

  - validation and comparison of propagated state

## Private means

The serialized state intended for local-only persistence, recovery, or
internal workflows.

Typical use cases:

  - local checkpointing

  - crash recovery

  - provider-specific persistence not meant for distribution

## Other considerations

For some providers, the state needed by the receiver is exactly the full
local state. In that case:

  - serialize\_private == serialize\_shareable

  - deserialize\_private == deserialize\_shareable

  - compare\_private == compare\_shareable

This is acceptable.

For other providers, private state may contain:

  - local-only seeds

  - local preferences

  - counters not meant to travel

  - cached derived material

  - information useful for local recovery but not required by receivers

In such cases, the provider must keep the formats distinct and document
the difference.

## What subscriber install expects

deserialize\_shareable() is the receiver-install contract.

A provider author should assume that the subscriber will receive only
the shareable blob and must reconstruct a usable decryption state from
it.

## What compare\_\* should verify

compare\_shareable() and compare\_private() should verify semantic
equivalence between the current installed state and the supplied
serialized representation according to the provider-defined format.

# Padding Contract

Padding behavior is governed by provider metadata:

  - pad\_apply

  - pad\_block\_size

This metadata tells the upper layer whether it must apply external
padding before encryption.

  - pad\_apply == true

The provider expects the upper layer to apply padding using
pad\_block\_size.

Implications:

plaintext handed to encrypt() is expected to already satisfy the
provider’s block-size requirements

the stack must apply and remove padding consistently outside the
provider

the provider should not silently depend on incompatible library-side
implicit padding unless that behavior is fully aligned with the actual
stack contract

pad\_apply == false

The upper layer must not apply external padding.

Implications:

stream ciphers and AEAD providers usually fall here

providers with internal framing and variable ciphertext expansion
usually fall here

providers whose crypto library handles padding internally may also fall
here if the outer stack must not pad

## Provider responsibility

The provider metadata must describe the actual upper-layer
responsibility, not an abstract cipher-family property.

This section is especially important because confusion about padding
ownership leads to interoperability bugs.

# Encrypt/Decrypt Contract

The encrypt/decrypt pair is the most important provider contract.

## Mandatory rule

decrypt() must accept exactly what encrypt() emits.

This includes all provider-specific framing choices.

## Outer layer assumptions

The outer layer assumes only that:

ciphertext is opaque provider output

output size follows the dvco\_buf\_t convention

AAD semantics are provider-defined within the ABI

shareable/private blobs are separate from ciphertext framing

## Other considerations

Provider may include internally

  - IV

  - nonce

  - authentication tag

  - algorithm header bytes

  - framing lengths

  - mode identifiers if provider-defined

## AAD behavior

AAD is optional and provider-defined.

A provider must clearly document whether it:

  - supports AAD

  - ignores AAD

  - rejects AAD as unsupported

## AEAD behavior

For AEAD providers:

  - nonce and tag may remain fully provider-internal

  - decrypt must fail if authentication/tag verification fails

  - failure should be reported as DVCO\_CP\_ERR\_CRYPTO

  - no plaintext should be exposed on auth failure

# Error Model and State Semantics

A provider should maintain a clear distinction between the following
classes of failures:

## Invalid argument failures

Caller used the API incorrectly.

Examples:

  - ctx == NULL

  - out == NULL

  - in\_data == NULL with non-zero input length

Return:

  - DVCO\_CP\_ERR\_INVALID\_ARG

## Bad state failures

The API call is valid, but the context is not in the right state.

Examples:

  - encrypt before rotate

  - serialize without active state

  - compare without installed state

Return:

  - DVCO\_CP\_ERR\_BAD\_STATE

## Parse failures

The input blob or ciphertext framing is malformed.

Examples:

  - too short

  - invalid declared lengths

  - structurally inconsistent framing

Return:

  - DVCO\_CP\_ERR\_PARSE

## Config failures

Provider-specific configuration is invalid.

Examples:

  - unsupported keybits value

  - unknown mandatory config option

  - inconsistent configuration combination

Return:

  - DVCO\_CP\_ERR\_CONFIG

## Crypto failures

Cryptographic processing failed despite structurally valid input.

Examples:

  - random generation failure

  - decryption failure

  - padding validation failure inside crypto engine

  - AEAD authentication failure

Return:

  - DVCO\_CP\_ERR\_CRYPTO

## Allocation failures

Memory allocation failed.

Return:

  - DVCO\_CP\_ERR\_ALLOC

  - Unsupported feature failures

## Feature exists in ABI but not in this provider.

Examples:

  - AAD not supported

  - private serialization not supported

Return:

  - DVCO\_CP\_ERR\_NOT\_SUPPORTED

## last\_error guidance

When a context exists, providers should set a short, stable, diagnostic
error string on meaningful failures.

The diagnostic string should help distinguish at least:

  - config errors

  - parse errors

  - state errors

  - crypto failures

# Plugin Entry Point

Each plugin shared library must export the canonical symbol:

int dvco\_cipher\_provider\_get\_api(const
dvco\_cipher\_provider\_api\_t \*\*out\_api);

The exported function must:

  - validate out\_api

  - return DVCO\_CP\_OK on success

  - return a non-OK code on failure

  - expose a stable static vtable for the provider

The symbol name must match:

DVCO\_CIPHER\_PROVIDER\_GET\_API\_SYMBOL

The loader resolves the provider entry point by the exact exported
symbol name defined by DVCO\_CIPHER\_PROVIDER\_GET\_API\_SYMBOL;
therefore the plugin must export that function under that exact name as
shown here:

\#define DVCO\_CIPHER\_PROVIDER\_GET\_API\_SYMBOL
"dvco\_cipher\_provider\_get\_api"

# Provider Implementation Checklist

A developer implementing a new provider should follow this checklist.

## Step 1: define provider identity

  - choose and fix the provider cid

  - define provider name, version, and description

  - report correct ABI version

## Step 2: define the provider context

  - create an internal struct behind dvco\_cipher\_ctx\_t

  - store all runtime cryptographic state there

  - store provider config resolved at create time

  - store diagnostics for last\_error()

## Step 3: define activation semantics

Decide clearly:

  - is the context usable immediately after create()?

  - or does it require rotate() or deserialization first?

Document that choice and enforce it consistently with BAD\_STATE.

## Step 4: define shareable format

Specify exactly what goes into the shareable blob:

  - key material

  - parameters

  - algorithm-specific state

  - lengths and framing

Ensure deserialize\_shareable() reconstructs usable state from that blob
alone.

## Step 5: define private format

Decide whether private and shareable are:

  - identical

  - related but distinct

  - completely different

Document the reason.

## Step 6: define ciphertext framing

Choose how encrypt() packages per-message metadata such as:

  - IV

  - nonce

  - tag

  - framing lengths

Then implement decrypt() to consume exactly that layout.

## Step 7: decide AAD policy

Document one of:

  - supported

  - ignored by design

  - rejected as unsupported

Apply the same policy consistently in both encrypt() and decrypt().

## Step 8: decide padding policy

Set pad\_apply and pad\_block\_size to match actual stack
responsibilities.

Do not leave this ambiguous.

## Step 9: implement two-call sizing correctly

For serialize\_\*, encrypt(), and decrypt():

  - support out-\>data == NULL

  - set required out-\>len

  - return BUFFER\_TOO\_SMALL correctly

## Step 10: implement robust input validation

Validate:

  - NULL pointers

  - length fields

  - blob structure

  - active state

  - algorithm-specific constraints

## Step 11: implement secure cleanup

On failure paths and destroy paths:

  - wipe sensitive key material where appropriate

  - do not leak partially initialized contexts

  - do not expose half-written state as success

## Step 12: implement useful diagnostics

Set last\_error() text on meaningful failures whenever a context exists.

## Step 13: verify interoperability

Test at minimum:

  - create -\> rotate -\> serialize\_shareable -\> encrypt

  - create -\> deserialize\_shareable -\> decrypt

  - compare\_shareable against same blob

  - serialize\_private / deserialize\_private if supported

  - buffer sizing two-call pattern

  - too-small buffer behavior

  - inactive-state failures

  - malformed blob parse failures

  - ciphertext round-trip

# Example Provider Classes

## Padded block cipher provider

Typical characteristics:

  - block cipher mode

  - may require or imply padding

  - may include IV in ciphertext framing

  - shareable blob typically includes keying material

  - decrypt may fail on malformed framing or cryptographic failure

Main documentation focus:

  - who owns padding

  - how IV is framed

  - whether library-side padding is relied upon

## Non-padded stream-like provider

Typical characteristics:

  - no outer-layer padding

  - ciphertext size roughly tracks plaintext size plus provider framing

  - per-message nonce or IV embedded in ciphertext

  - shareable blob usually contains keying material and provider state

Main documentation focus:

  - nonce/IV framing

  - no padding assumptions

  - exact decrypt acceptance contract

## AEAD provider

Typical characteristics:

  - no outer-layer padding

  - ciphertext contains nonce and authentication tag in provider-defined
    format

  - decrypt may fail due to authentication failure

  - AAD may be supported and must match exactly if used

Main documentation focus:

  - nonce/tag framing

  - AAD semantics

  - distinction between parse failure and auth failure

  - no plaintext output on auth failure

# Final Notes for Provider Authors

The most important implementation rule is consistency.

A provider is free to choose its own:

  - shareable blob format

  - private blob format

  - ciphertext framing

  - AAD policy

  - internal state model

But once chosen, these must remain internally coherent across:

  - create

  - rotate

  - serialize

  - deserialize

  - encrypt

  - decrypt

  - compare

  - destroy

The DVCO core relies on the provider ABI to be stable, opaque, and
predictable. A well-implemented provider is not one that merely encrypts
and decrypts, but one that makes lifecycle, state transitions,
serialization, error handling, and interoperability explicit and
reliable.

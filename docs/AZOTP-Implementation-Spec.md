# AZOTP Implementation Specification

## Scope

This document describes the implemented `pkg/azotp` package and its runnable examples. It is the authoritative specification for the current code in this repository.

## Protocol Summary

AZOTP is a human-centered one-time password protocol with two modes:

- Reference Mode: deterministic OTP generation from a secret and canonical context
- Random Mode: cryptographically random OTP generation from entropy

The package is designed for trusted-device, mobile-first verification flows where short human-readable codes are preferred over longer numeric OTPs.

## Locked Protocol Traits

- OTP length: `4`
- OTP alphabet: lowercase `a-z`
- Display form: uppercase recommended
- Verification form: case-insensitive
- Visible expiry: `60s`
- Backend grace window: `90s`
- Attempts per OTP: `1`
- Default mode: `reference`
- Secret default: `azotp`
- Challenge ID length: `12`

## Data Model

### Binding

A binding identifies the pre-authentication context for a challenge.

Fields:

- `provider`
- `device_id`
- `session`
- `nonce`

The implemented Go type is:

```go
type Binding struct {
    Provider  string
    SessionID string
    DeviceID  string
    Nonce     string
}
```

Canonical binding order:

1. provider
2. device
3. session
4. nonce

Canonical form:

```text
v1|<len(provider)>:<provider>|<len(device)>:<device>|<len(session)>:<session>|<len(nonce)>:<nonce>
```

### Challenge

A challenge records the issued OTP and its timing state.

Fields:

- `ID`
- `Mode`
- `Context`
- `OTP`
- `Binding`
- `IssuedAt`
- `VisibleExpiresAt`
- `GraceExpiresAt`

Internal state tracked by the implementation:

- `pending`
- `verified`
- `invalidated`

## Reference Mode

Reference Mode derives the OTP deterministically.

Formula:

```text
hash = blake3(server_secret + canonical_context)
otp  = base26(hash)[0:4]
```

Canonical context for binding issuance:

```text
v1|<len(provider)>:<provider>|<len(device)>:<device>|<len(session)>:<session>|<len(nonce)>:<nonce>
```

Reference Mode uses a time window of 60 seconds:

```text
window = unix_time / 60
```

The canonical reference input is:

```text
v1|<len(context)>:<context>|<window>
```

### Secret Handling

The core package does not read environment variables.

Secret injection is handled by the caller through:

```go
type Config struct {
    ServerSecret string
}
```

Rules:

- empty or whitespace-only secret values fall back to `azotp`
- the spec environment variable name is `AZOTP_SERVER_SECRET`
- examples show env loading in the wrapper layer, not inside the core package

## Random Mode

Random Mode generates a 4-character OTP from cryptographically secure entropy.

Flow:

```text
secure_random_bytes -> base26 -> first 4 chars
```

The implementation uses a reader supplied by the caller. Random Mode is explicit and separate from Reference Mode.

## Validation Rules

### OTP Validation

- length must be exactly 4 characters
- internal storage is lowercase
- verification accepts uppercase or lowercase input
- invalid characters reject the OTP

### Binding Validation

- provider must be non-empty and trimmed
- device_id must be non-empty and trimmed
- session must be non-empty and trimmed
- nonce must be non-empty and trimmed
- each field must be within the binding length limit

### Context Validation

- context must be non-empty
- context must be trimmed

## Verification Rules

Verification is single-attempt.

Behavior:

- a verified challenge cannot be reused
- a failed attempt invalidates the challenge immediately
- a binding mismatch invalidates the challenge immediately
- expired challenges are rejected

Expiry semantics:

- visible expiry is inclusive at 60 seconds
- grace expiry is inclusive at 90 seconds

## Challenge IDs

Challenge IDs are generated from entropy and encoded with the local `id57` package.

- length: 12
- purpose: human-readable challenge identifiers

## Public API

The current package API includes:

- `DefaultConfig()`
- `TimeWindow(now time.Time) int64`
- `ValidateContext(context string) error`
- `CanonicalReferenceInput(context string, now time.Time) (string, error)`
- `GenerateReference(context string, now time.Time, config Config) (string, error)`
- `Generate(context string, now time.Time) (string, error)`
- `GenerateWithSecret(context, serverSecret string, now time.Time) (string, error)`
- `GenerateRandom(reader io.Reader) (string, error)`
- `Validate(value string) error`
- `IsValid(value string) bool`
- `ValidateBinding(binding Binding) error`
- `CanonicalBindingInput(binding Binding) (string, error)`
- `IssueReference(binding Binding, now time.Time, reader io.Reader, config Config) (*Challenge, error)`
- `Issue(binding Binding, now time.Time, reader io.Reader) (*Challenge, error)`
- `IssueRandom(binding Binding, now time.Time, reader io.Reader) (*Challenge, error)`
- `Cooldown(sequence int) time.Duration`
- `(*Challenge).Verify(otp string, binding Binding, now time.Time) error`
- `(*Challenge).State() State`
- `(*Challenge).IsVisibleExpired(now time.Time) bool`
- `(*Challenge).IsGraceExpired(now time.Time) bool`

## Examples

### Reference Mode Example

`examples/reference-mode` demonstrates direct use of the core package with caller-supplied configuration.

### Service Wrapper Example

`examples/service-wrapper` demonstrates the intended service-layer boundary:

- read `AZOTP_SERVER_SECRET` from the environment
- apply the default secret fallback
- inject `Config` into the core package
- keep env loading outside the core implementation

## Non-Goals

This package does not implement:

- WebAuthn / Passkeys
- OAuth2 / OIDC
- hardware security keys
- high-assurance identity systems
- secret storage or rotation policy
- environment variable loading inside the core package

## Notes

This implementation intentionally keeps the core package deterministic and pure. Service-specific concerns belong in the caller layer.

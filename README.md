# azotp

Human-centered one-time passwords for the AZOTP v0.1.0 reference architecture.

> **Status:** v0.1.0 HARDENED — Initial release with cryptographically-strict specification, constant-time comparison, binding-secured deterministic derivation, and replay-safe verification.

## Locked traits

- Default mode: `reference`
- OTP format: `4` base57 characters
- Alphabet: `ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz123456789`
- Alphabet exclusions: `I`, `O`, `l`, `0`
- Visible expiry: `60s`
- Backend grace window: `90s`
- Attempts per OTP: `1`
- Binding: provider + platform_type + device + session + nonce + time_bucket
- Allowed `platform_type`: `web`, `ios`, `android`, `desktop`, `embedded`, `other`
- Config secret: `Config{ServerSecret: ...}` with default `azotp`

## Install

```sh
go get github.com/nhanpnt22/azotp
```

## Import

```go
import "github.com/nhanpnt22/azotp"
```

## API

```go
type Config struct {
    ServerSecret string
}

func DefaultConfig() Config
func TimeWindow(now time.Time) int64
func ValidateContext(context string) error
func CanonicalReferenceInput(context string, now time.Time) (string, error)
func GenerateReference(context string, now time.Time, config Config) (string, error)
func Generate(context string, now time.Time) (string, error)
func GenerateWithSecret(context, serverSecret string, now time.Time) (string, error)
func MustGenerate(context string, now time.Time) string
func GenerateRandom(reader io.Reader) (string, error)
func MustGenerateRandom(reader io.Reader) string
func Validate(value string) error
func IsValid(value string) bool
func ValidateBinding(binding Binding) error
func CanonicalBindingInput(binding Binding, now time.Time) (string, error)
func CanonicalContextWithTimeBucket(binding Binding, now time.Time) (string, error)
func IssueReference(binding Binding, now time.Time, reader io.Reader, config Config) (*Challenge, string, error)
func Issue(binding Binding, now time.Time, reader io.Reader) (*Challenge, string, error)
func IssueRandom(binding Binding, now time.Time, reader io.Reader) (*Challenge, string, error)
func Cooldown(sequence int) time.Duration
```

```go
type Binding struct {
    Provider     string
    PlatformType string
    SessionID    string
    DeviceID     string
    Nonce        string
}

type Challenge struct {
    ID               string
    Mode             Mode
    Context          string
    Binding          Binding
    IssuedAt         time.Time
    VisibleExpiresAt time.Time
    GraceExpiresAt   time.Time
}

func (challenge *Challenge) Verify(otp string, binding Binding, now time.Time) error
func (challenge *Challenge) State() State
func (challenge *Challenge) IsVisibleExpired(now time.Time) bool
func (challenge *Challenge) IsGraceExpired(now time.Time) bool
```

## Example

See `examples/reference-mode` for a runnable program that injects `Config` directly into the core package, and `examples/service-wrapper` for a service-layer wrapper that owns env loading and secret fallback.

## Security

This package implements the AZOTP v0.1.0 **HARDENED** specification with the following guarantees:

- **Deterministic Derivation:** Reference mode uses BLAKE3-256(server_secret + canonical_context), projected to base57 alphabet
- **Constant-Time Comparison:** OTP and binding verification use `crypto/subtle.ConstantTimeCompare` to prevent timing side-channels
- **Single-Use Enforcement:** Each OTP validates exactly once; wrong OTP, wrong binding, or expiry invalidates immediately
- **Replay Protection:** Binding hash (BLAKE3-128) + single-use in package; nonce uniqueness and session semantics must be enforced by the service storage/transaction layer
- **Cryptographic Hash:** BLAKE3-128 for both OTP hashes and binding hashes (16 bytes exact)
- **Case Sensitivity:** OTP input is case-sensitive; no normalization is performed

## Migration Note

- v0.1.0 now uses base57 output instead of base26 lowercase.
- Existing integrations must stop uppercasing/lowercasing OTP input.
- Legacy base26-only OTP validators are incompatible and must be updated.

## Requirements

- Go 1.24.0 or later
- External dependency: `lukechampine.com/blake3` (BLAKE3 hash implementation)
- Internal dependency: `github.com/nhanpnt22/id57` (challenge ID generation)

## Testing

This package includes comprehensive test coverage:

- **Coverage:** 90.3% of statements
- **Test Suite:** 52 test functions covering:
  - OTP generation (deterministic reference mode, random mode)
  - Challenge lifecycle (issuance, verification, state transitions)
  - Binding validation (all platform types, edge cases, error conditions)
  - Expiry handling (visible window, grace window, boundaries)
  - Hash integrity (BLAKE3-128 correctness, immutability)
  - Error paths (nil readers, invalid input, expired OTPs, binding mismatches)
  - Time window calculations and cooldown escalation
  - Nil pointer safety

- **Test Vectors:** 14 formal test vectors from spec in `docs/tests/azotp_test_vectors.json`
  - Deterministic derivation validation
  - Platform isolation verification
  - Time bucket sensitivity
  - Cross-vector consistency

- **Examples:** Two runnable examples with integration tests
  - `examples/reference-mode/` — Direct config injection
  - `examples/service-wrapper/` — Environment-based secret loading

Run tests with:
```sh
go test -v -cover ./...
```

## Changelog

### v0.1.0 (2026-05-15)

**Initial Release**

- Implements AZOTP v0.1.0 HARDENED specification
- BLAKE3-256 deterministic OTP derivation (reference mode)
- BLAKE3-128 constant-time hashing for OTP and binding verification
- Single-use enforcement with replay protection
- Comprehensive binding validation (provider, platform, device, session, nonce)
- Challenge lifecycle management (pending → verified/invalidated)
- Time-windowed verification (60s visible, 90s backend grace window)
- Entropy-backed challenge ID generation via id57
- Examples: reference-mode direct config injection, service-wrapper with env loading
- **90.3% test coverage** with **52 comprehensive tests**
- Formal specification document and 14 test vectors included

## Specification

**Formal Specification:** `docs/AZOTP — STRICT IMPLEMENTATION CONTRACT-v0.1.0.txt`

This document defines the immutable protocol contract, including:
- Cryptographic algorithms (BLAKE3-256, BLAKE3-128)
- Canonicalization rules (length-prefixed format)
- Binding field requirements and validation
- Expiry semantics (visible vs. grace window)
- Single-use enforcement and replay protection
- Constant-time comparison requirements

**Test Vectors:** `docs/tests/azotp_test_vectors.json` (14 vectors)

Provides byte-exact test data for:
- Canonical context formation
- Deterministic OTP generation
- Cross-language implementation validation
- Regression testing

## Notes

- Reference Mode is the default. It computes `blake3-256(server_secret + canonical_context)` and projects the digest into base57 output.
- `AZOTP_SERVER_SECRET` is supplied by the caller via `Config.ServerSecret` and defaults to `azotp` when empty.
- Challenge IDs use the local `id57` package for 12-character human-readable identifiers.
- Binding canonicalization is provider-aware and uses the same exact length-prefixed style used by the sibling deterministic packages.
- Accepted `platform_type` values are `web`, `ios`, `android`, `desktop`, `embedded`, and `other`.
- Verification is single-attempt: wrong OTP, wrong binding, or expiry invalidates the challenge immediately, and OTP input is case-sensitive.
- Random Mode remains available explicitly for fallback or interoperability flows.

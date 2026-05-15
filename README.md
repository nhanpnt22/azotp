# azotp

Human-centered one-time passwords for the AZOPT v0.1.0 reference architecture.

## Locked traits

- Default mode: `reference`
- OTP format: `4` lowercase letters
- Alphabet: `a-z`
- Visible expiry: `60s`
- Backend grace window: `90s`
- Attempts per OTP: `1`
- Binding: provider + device + session + nonce
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
func CanonicalBindingInput(binding Binding) (string, error)
func IssueReference(binding Binding, now time.Time, reader io.Reader, config Config) (*Challenge, error)
func Issue(binding Binding, now time.Time, reader io.Reader) (*Challenge, error)
func IssueRandom(binding Binding, now time.Time, reader io.Reader) (*Challenge, error)
func Cooldown(sequence int) time.Duration
```

```go
type Binding struct {
    Provider  string
    SessionID string
    DeviceID  string
    Nonce     string
}

type Challenge struct {
    ID               string
    Mode             Mode
    Context          string
    OTP              string
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

## Spec

See `docs/AZOTP-Implementation-Spec.md` for the implemented package contract.

## Notes

- Reference Mode is the default. It computes `blake3(azotp_server_secret + canonical_context_with_time_window)` and projects the digest into base26 lowercase output.
- `AZOTP_SERVER_SECRET` is supplied by the caller via `Config.ServerSecret` and defaults to `azotp` when empty.
- Challenge IDs use the local `id57` package for 12-character human-readable identifiers.
- Binding canonicalization is provider-aware and uses the same exact length-prefixed style used by the sibling deterministic packages.
- Verification is single-attempt: wrong OTP, wrong binding, or expiry invalidates the challenge immediately, and OTP input is case-insensitive.
- Random Mode remains available explicitly for fallback or interoperability flows.# azotp

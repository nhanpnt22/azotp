// Package azotp implements the AZOTP v0.1.0 HARDENED cryptographically-strict
// one-time password protocol with binding-secured, byte-level deterministic
// derivation and replay-safe verification.
//
// Locked protocol traits (IMMUTABLE):
//
//   - OTP format: 4 characters from a-z alphabet
//   - Deterministic derivation hash: BLAKE3-256
//   - Stored hash size: BLAKE3-128 (16 bytes exact)
//   - Binding hash: BLAKE3-128 of canonical context
//   - Visible expiry: 60s
//   - Backend grace window: 90s
//   - Validation attempts per OTP: exactly 1 (single-use)
//   - Binding: provider + device_id + session_id + nonce + time_bucket
//   - Canonical format: v1|<len>:<value>|<len>:<value>|...
//   - Constant-time comparison: REQUIRED
//   - Replay protection: binding_hash + service-enforced nonce uniqueness + single-use
package azotp

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/nhanpnt22/id57"
	"lukechampine.com/blake3"
)

const (
	Version           = "v0.1.0"
	ProtocolVersion   = "1"
	Alphabet          = "abcdefghijklmnopqrstuvwxyz"
	OTPLength         = 4
	ChallengeIDLength = 12
	VisibleExpiry     = 60 * time.Second
	GraceWindow       = 90 * time.Second
	WindowStep        = 60 * time.Second
	MaxBindingLength  = 256
	DefaultSecret     = "azotp"
	BindingHashSize   = 16 // BLAKE3-128: 16 bytes exact
	OTPHashSize       = 16 // BLAKE3-128: 16 bytes exact
)

var otpBase = big.NewInt(int64(len(Alphabet)))

var validPlatformTypes = map[string]struct{}{
	"web":      {},
	"ios":      {},
	"android":  {},
	"desktop":  {},
	"embedded": {},
	"other":    {},
}

type Mode string

const (
	ModeReference Mode = "reference"
	ModeRandom    Mode = "random"
)

type State string

const (
	StatePending     State = "pending"
	StateVerified    State = "verified"
	StateInvalidated State = "invalidated"
)

var (
	alphabetSet [256]bool

	ErrInvalidOTP        = errors.New("azotp: invalid otp")
	ErrChallengeRequired = errors.New("azotp: challenge is required")
	ErrBindingRequired   = errors.New("azotp: binding is required")
	ErrBindingMismatch   = errors.New("azotp: binding mismatch")
	ErrContextRequired   = errors.New("azotp: context is required")
	ErrOTPRejected       = errors.New("azotp: otp rejected")
	ErrOTPExpired        = errors.New("azotp: otp expired")
	ErrOTPUsed           = errors.New("azotp: otp already used")
	ErrOTPInvalidated    = errors.New("azotp: otp invalidated")
	ErrEntropyDepleted   = errors.New("azotp: entropy source exhausted")
)

func init() {
	for index := 0; index < len(Alphabet); index++ {
		alphabetSet[Alphabet[index]] = true
	}
}

// blake3_128 computes BLAKE3-128 (first 16 bytes of BLAKE3-256)
func blake3_128(data []byte) [BindingHashSize]byte {
	digest := blake3.Sum256(data)
	var result [BindingHashSize]byte
	copy(result[:], digest[:BindingHashSize])
	return result
}

// constantTimeEqual performs constant-time comparison of two byte slices
// to prevent timing side-channel attacks on OTP verification.
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

type Binding struct {
	Provider     string
	PlatformType string
	SessionID    string
	DeviceID     string
	Nonce        string
}

type Config struct {
	ServerSecret string
}

func DefaultConfig() Config {
	return Config{ServerSecret: DefaultSecret}
}

func (config Config) serverSecret() string {
	if strings.TrimSpace(config.ServerSecret) == "" {
		return DefaultSecret
	}

	return config.ServerSecret
}

type Challenge struct {
	ID               string
	Mode             Mode
	Context          string // Canonical context string
	OTPHash          []byte // BLAKE3-128 hash of OTP (16 bytes)
	BindingHash      []byte // BLAKE3-128 hash of canonical context (16 bytes)
	Binding          Binding
	IssuedAt         time.Time
	VisibleExpiresAt time.Time
	GraceExpiresAt   time.Time

	state         State
	AttemptedAt   time.Time
	VerifiedAt    time.Time
	InvalidatedAt time.Time
}

func Validate(value string) error {
	_, err := normalizeOTP(value)
	return err
}

func IsValid(value string) bool {
	return Validate(value) == nil
}

func ValidateBinding(binding Binding) error {
	if err := validateBindingPart("provider", binding.Provider); err != nil {
		return err
	}
	if err := validatePlatformType(binding.PlatformType); err != nil {
		return err
	}
	if err := validateBindingPart("session_id", binding.SessionID); err != nil {
		return err
	}
	if err := validateBindingPart("device_id", binding.DeviceID); err != nil {
		return err
	}
	if err := validateBindingPart("nonce", binding.Nonce); err != nil {
		return err
	}

	return nil
}

func CanonicalBindingInput(binding Binding, now time.Time) (string, error) {
	if err := ValidateBinding(binding); err != nil {
		return "", err
	}

	timeBucket := fmt.Sprintf("%d", TimeWindow(now))

	// Strict field order: version, provider, platform_type, device_id,
	// session_id, nonce, time_bucket.
	return fmt.Sprintf(
		"v:%d:%s|p:%d:%s|pt:%d:%s|d:%d:%s|s:%d:%s|n:%d:%s|t:%d:%s",
		len(ProtocolVersion), ProtocolVersion,
		len(binding.Provider), binding.Provider,
		len(binding.PlatformType), binding.PlatformType,
		len(binding.DeviceID), binding.DeviceID,
		len(binding.SessionID), binding.SessionID,
		len(binding.Nonce), binding.Nonce,
		len(timeBucket), timeBucket,
	), nil
}

// CanonicalContextWithTimeBucket includes the time_bucket in the canonical context.
// This is used for binding hash computation and reference mode OTP generation.
func CanonicalContextWithTimeBucket(binding Binding, now time.Time) (string, error) {
	return CanonicalBindingInput(binding, now)
}

func TimeWindow(now time.Time) int64 {
	return now.Unix() / int64(WindowStep/time.Second)
}

func ValidateContext(context string) error {
	if strings.TrimSpace(context) != context || context == "" {
		return ErrContextRequired
	}

	return nil
}

func CanonicalReferenceInput(context string, now time.Time) (string, error) {
	if err := ValidateContext(context); err != nil {
		return "", err
	}
	_ = now

	// Deterministic derivation consumes caller-provided canonical context bytes.
	return context, nil
}

func GenerateReference(context string, now time.Time, config Config) (string, error) {
	return GenerateWithSecret(context, config.serverSecret(), now)
}

func Generate(context string, now time.Time) (string, error) {
	return GenerateReference(context, now, DefaultConfig())
}

func GenerateWithSecret(context, serverSecret string, now time.Time) (string, error) {
	return generateReferenceWithSecret(context, serverSecret, now)
}

func MustGenerate(context string, now time.Time) string {
	value, err := Generate(context, now)
	if err != nil {
		panic(err)
	}

	return value
}

func GenerateRandom(reader io.Reader) (string, error) {
	if reader == nil {
		reader = strings.NewReader("")
	}

	buffer := make([]byte, OTPLength)
	index := 0
	for index < OTPLength {
		value, err := readAlphabetByte(reader)
		if err != nil {
			return "", err
		}
		buffer[index] = value
		index++
	}

	return string(buffer), nil
}

func MustGenerateRandom(reader io.Reader) string {
	value, err := GenerateRandom(reader)
	if err != nil {
		panic(err)
	}

	return value
}

func IssueReference(binding Binding, now time.Time, reader io.Reader, config Config) (*Challenge, string, error) {
	if err := ValidateBinding(binding); err != nil {
		return nil, "", err
	}
	if reader == nil {
		return nil, "", ErrEntropyDepleted
	}

	id, err := generateChallengeID(reader)
	if err != nil {
		return nil, "", err
	}

	// Generate OTP using canonical context with time_bucket.
	bindingContext, err := CanonicalBindingInput(binding, now)
	if err != nil {
		return nil, "", err
	}

	otp, err := GenerateReference(bindingContext, now, config)
	if err != nil {
		return nil, "", err
	}
	otpHash := blake3_128([]byte(otp))

	return newChallenge(ModeReference, bindingContext, binding, id, otpHash[:], now), otp, nil
}

func Issue(binding Binding, now time.Time, reader io.Reader) (*Challenge, string, error) {
	return IssueReference(binding, now, reader, DefaultConfig())
}

func IssueRandom(binding Binding, now time.Time, reader io.Reader) (*Challenge, string, error) {
	if err := ValidateBinding(binding); err != nil {
		return nil, "", err
	}
	if reader == nil {
		return nil, "", ErrEntropyDepleted
	}

	id, err := generateChallengeID(reader)
	if err != nil {
		return nil, "", err
	}
	otp, err := GenerateRandom(reader)
	if err != nil {
		return nil, "", err
	}
	otpHash := blake3_128([]byte(otp))

	bindingContext, err := CanonicalBindingInput(binding, now)
	if err != nil {
		return nil, "", err
	}

	return newChallenge(ModeRandom, bindingContext, binding, id, otpHash[:], now), otp, nil
}

func (challenge *Challenge) Verify(otp string, binding Binding, now time.Time) error {
	if challenge == nil {
		return ErrChallengeRequired
	}

	switch challenge.state {
	case StateVerified:
		return ErrOTPUsed
	case StateInvalidated:
		return ErrOTPInvalidated
	}

	if !now.Before(challenge.GraceExpiresAt) {
		challenge.invalidate(now)
		return ErrOTPExpired
	}

	if err := ValidateBinding(binding); err != nil {
		challenge.invalidate(now)
		return err
	}

	// Verify binding hash first for replay protection
	recomputedContext, err := CanonicalBindingInput(binding, challenge.IssuedAt)
	if err != nil {
		challenge.invalidate(now)
		return err
	}

	// Compute binding hash for verification
	bindingHashInput := recomputedContext
	recomputedHash := blake3_128([]byte(bindingHashInput))
	if len(challenge.BindingHash) != BindingHashSize || len(challenge.OTPHash) != OTPHashSize {
		challenge.invalidate(now)
		return ErrOTPInvalidated
	}

	// Constant-time comparison of binding hashes
	if !constantTimeEqual(recomputedHash[:], challenge.BindingHash) {
		challenge.invalidate(now)
		return ErrBindingMismatch
	}

	normalizedOTP, err := normalizeOTP(otp)
	if err != nil {
		challenge.invalidate(now)
		return err
	}

	// Compute OTP hash for constant-time comparison
	otpHash := blake3_128([]byte(normalizedOTP))

	// Constant-time OTP comparison
	if !constantTimeEqual(otpHash[:], challenge.OTPHash) {
		challenge.invalidate(now)
		return ErrOTPRejected
	}

	challenge.state = StateVerified
	challenge.AttemptedAt = now
	challenge.VerifiedAt = now
	return nil
}

func (challenge *Challenge) State() State {
	if challenge == nil {
		return StateInvalidated
	}

	return challenge.state
}

func (challenge *Challenge) IsVisibleExpired(now time.Time) bool {
	if challenge == nil {
		return true
	}

	return !now.Before(challenge.VisibleExpiresAt)
}

func (challenge *Challenge) IsGraceExpired(now time.Time) bool {
	if challenge == nil {
		return true
	}

	return !now.Before(challenge.GraceExpiresAt)
}

func Cooldown(sequence int) time.Duration {
	switch {
	case sequence <= 0:
		return 0
	case sequence == 1:
		return 60 * time.Second
	case sequence == 2:
		return 5 * time.Minute
	case sequence == 3:
		return 15 * time.Minute
	default:
		return time.Hour
	}
}

func (challenge *Challenge) invalidate(now time.Time) {
	challenge.state = StateInvalidated
	challenge.AttemptedAt = now
	challenge.InvalidatedAt = now
}

func otpFromDigest(digest []byte) (string, error) {
	number := new(big.Int).SetBytes(digest)
	modulus := new(big.Int)
	buffer := make([]byte, OTPLength)

	for index := 0; index < OTPLength; index++ {
		number.DivMod(number, otpBase, modulus)
		buffer[index] = Alphabet[modulus.Int64()]
	}

	value := string(buffer)
	if err := Validate(value); err != nil {
		return "", err
	}

	return value, nil
}

func generateReferenceWithSecret(context, serverSecret string, now time.Time) (string, error) {
	canonical, err := CanonicalReferenceInput(context, now)
	if err != nil {
		return "", err
	}

	// Deterministic mode derives OTP from BLAKE3-256(secret + canonical_context).
	fullInput := serverSecret + canonical
	digest := blake3.Sum256([]byte(fullInput))
	return otpFromDigest(digest[:])
}

func newChallenge(mode Mode, context string, binding Binding, id string, otpHash []byte, now time.Time) *Challenge {
	// Compute binding hash from context (BLAKE3-128)
	// For reference mode, context is canonical binding input
	bindingHashInput := context
	if bindingHashInput == "" {
		// For random mode, compute from binding
		if ctx, err := CanonicalBindingInput(binding, now); err == nil {
			bindingHashInput = ctx
		}
	}
	bindingHash := blake3_128([]byte(bindingHashInput))

	return &Challenge{
		ID:               id,
		Mode:             mode,
		Context:          context,
		OTPHash:          append([]byte(nil), otpHash...),
		BindingHash:      bindingHash[:],
		Binding:          binding,
		IssuedAt:         now,
		VisibleExpiresAt: now.Add(VisibleExpiry),
		GraceExpiresAt:   now.Add(GraceWindow),
		state:            StatePending,
	}
}

func generateChallengeID(reader io.Reader) (string, error) {
	entropy := make([]byte, 16)
	if _, err := io.ReadFull(reader, entropy); err != nil {
		return "", fmt.Errorf("%w: %v", ErrEntropyDepleted, err)
	}

	return id57.FromDigest(entropy, ChallengeIDLength)
}

func readAlphabetByte(reader io.Reader) (byte, error) {
	var sample [1]byte
	for {
		if _, err := io.ReadFull(reader, sample[:]); err != nil {
			return 0, fmt.Errorf("%w: %v", ErrEntropyDepleted, err)
		}
		// Rejection sampling keeps distribution uniform for base26.
		// Largest multiple of 26 below 256 is 234.
		if sample[0] >= 234 {
			continue
		}
		return Alphabet[int(sample[0])%len(Alphabet)], nil
	}
}

func validateBindingPart(name, value string) error {
	if strings.TrimSpace(value) != value || value == "" {
		return fmt.Errorf("%w: %s must be non-empty and trimmed", ErrBindingRequired, name)
	}
	if len(value) > MaxBindingLength {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrBindingRequired, name, MaxBindingLength)
	}

	return nil
}

func validatePlatformType(value string) error {
	if err := validateBindingPart("platform_type", value); err != nil {
		return err
	}
	if value != strings.ToLower(value) {
		return fmt.Errorf("%w: platform_type must be lowercase", ErrBindingRequired)
	}
	if _, ok := validPlatformTypes[value]; !ok {
		return fmt.Errorf("%w: platform_type must be one of web|ios|android|desktop|embedded|other", ErrBindingRequired)
	}

	return nil
}

func normalizeOTP(value string) (string, error) {
	if len(value) != OTPLength {
		return "", fmt.Errorf("%w: length must be %d", ErrInvalidOTP, OTPLength)
	}

	normalized := strings.ToLower(value)
	buffer := make([]byte, OTPLength)
	for index := 0; index < len(normalized); index++ {
		ch := normalized[index]
		if !alphabetSet[ch] {
			return "", fmt.Errorf("%w: character %q at index %d", ErrInvalidOTP, value[index], index)
		}
		buffer[index] = ch
	}

	return string(buffer), nil
}

package azotp

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestGenerateUsesDefaultSecretDeterministically(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	context := "v:1:1|p:4:zalo|pt:3:web|d:7:web:abc|s:4:x7d9|n:4:p4t2|t:8:29119680"

	left, err := Generate(context, now)
	if err != nil {
		t.Fatalf("Generate: unexpected error: %v", err)
	}
	right, err := Generate(context, now)
	if err != nil {
		t.Fatalf("Generate repeat: unexpected error: %v", err)
	}

	if left != right {
		t.Fatalf("Generate should be deterministic: %q != %q", left, right)
	}
	if err := Validate(left); err != nil {
		t.Fatalf("Generate output should be valid OTP: %v", err)
	}
}

func TestGenerateUsesConfigSecret(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	context := "v:1:1|p:4:zalo|pt:3:web|d:7:web:abc|s:4:x7d9|n:4:p4t2|t:8:29119680"
	config := Config{ServerSecret: "custom-secret"}

	got, err := GenerateReference(context, now, config)
	if err != nil {
		t.Fatalf("GenerateReference with config secret: unexpected error: %v", err)
	}
	want, err := GenerateWithSecret(context, "custom-secret", now)
	if err != nil {
		t.Fatalf("GenerateWithSecret: unexpected error: %v", err)
	}

	if got != want {
		t.Fatalf("Generate with env secret = %q, want %q", got, want)
	}
}

func TestGenerateRandomKnownValue(t *testing.T) {
	otp, err := GenerateRandom(bytes.NewReader([]byte{0, 1, 2, 3}))
	if err != nil {
		t.Fatalf("GenerateRandom: unexpected error: %v", err)
	}

	if otp != "abcd" {
		t.Fatalf("GenerateRandom = %q, want %q", otp, "abcd")
	}
}

func TestGenerateRandomRejectsInvalidEntropy(t *testing.T) {
	_, err := GenerateRandom(bytes.NewReader(nil))
	if !errors.Is(err, ErrEntropyDepleted) {
		t.Fatalf("GenerateRandom(empty reader) = %v, want ErrEntropyDepleted", err)
	}
}

func TestValidate(t *testing.T) {
	if err := Validate("KQmX"); err != nil {
		t.Fatalf("Validate(valid): unexpected error: %v", err)
	}
	if err := Validate("zYZa"); err != nil {
		t.Fatalf("Validate(case-insensitive valid): unexpected error: %v", err)
	}

	for _, value := range []string{"abc", "abcde", "ab0d", "ab1d", "ab-d", "ab_d"} {
		if err := Validate(value); !errors.Is(err, ErrInvalidOTP) {
			t.Fatalf("Validate(%q) = %v, want ErrInvalidOTP", value, err)
		}
	}
}

func TestCanonicalBindingInput(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}

	got, err := CanonicalBindingInput(binding, now)
	if err != nil {
		t.Fatalf("CanonicalBindingInput: unexpected error: %v", err)
	}

	want := "v:1:1|p:4:zalo|pt:3:web|d:5:dev-1|s:6:sess-1|n:7:nonce-1|t:8:29119680"
	if got != want {
		t.Fatalf("CanonicalBindingInput = %q, want %q", got, want)
	}
}

func TestCanonicalReferenceInputUsesTimeWindow(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	context := "v:1:1|p:4:zalo|pt:3:web|d:7:web:abc|s:4:x7d9|n:4:p4t2|t:8:29119680"
	got, err := CanonicalReferenceInput(context, now)
	if err != nil {
		t.Fatalf("CanonicalReferenceInput: unexpected error: %v", err)
	}

	want := context
	if got != want {
		t.Fatalf("CanonicalReferenceInput = %q, want %q", got, want)
	}
}

func TestIssueAndVerifySuccess(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, issuedOTP, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if err != nil {
		t.Fatalf("Issue: unexpected error: %v", err)
	}

	if challenge.ID != strings.Repeat("A", ChallengeIDLength) {
		t.Fatalf("challenge.ID = %q, want %q", challenge.ID, strings.Repeat("A", ChallengeIDLength))
	}
	if challenge.Mode != ModeReference {
		t.Fatalf("challenge.Mode = %q, want %q", challenge.Mode, ModeReference)
	}
	if challenge.Context != "v:1:1|p:4:zalo|pt:3:web|d:5:dev-1|s:6:sess-1|n:7:nonce-1|t:8:29119680" {
		t.Fatalf("challenge.Context = %q, want canonical binding context", challenge.Context)
	}
	wantOTP, err := GenerateReference(challenge.Context, now, DefaultConfig())
	if err != nil {
		t.Fatalf("Generate(challenge.Context): unexpected error: %v", err)
	}
	if issuedOTP != wantOTP {
		t.Fatalf("issued OTP = %q, want %q", issuedOTP, wantOTP)
	}
	if challenge.State() != StatePending {
		t.Fatalf("challenge.State() = %q, want %q", challenge.State(), StatePending)
	}

	verifyAt := now.Add(75 * time.Second)
	if err := challenge.Verify(wantOTP, binding, verifyAt); err != nil {
		t.Fatalf("Verify(success): unexpected error: %v", err)
	}
	if challenge.State() != StateVerified {
		t.Fatalf("challenge.State() after verify = %q, want %q", challenge.State(), StateVerified)
	}
	if err := challenge.Verify(wantOTP, binding, verifyAt); !errors.Is(err, ErrOTPUsed) {
		t.Fatalf("Verify(reuse) = %v, want ErrOTPUsed", err)
	}
}

func TestVerifyWrongOTPInvalidatesImmediately(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, _, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if err != nil {
		t.Fatalf("Issue: unexpected error: %v", err)
	}

	if err := challenge.Verify("aaac", binding, now.Add(10*time.Second)); !errors.Is(err, ErrOTPRejected) {
		t.Fatalf("Verify(wrong otp) = %v, want ErrOTPRejected", err)
	}
	if challenge.State() != StateInvalidated {
		t.Fatalf("challenge.State() after wrong otp = %q, want %q", challenge.State(), StateInvalidated)
	}
	if err := challenge.Verify("aaaa", binding, now.Add(11*time.Second)); !errors.Is(err, ErrOTPInvalidated) {
		t.Fatalf("Verify(after invalidation) = %v, want ErrOTPInvalidated", err)
	}
}

func TestVerifyBindingMismatchInvalidates(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, _, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if err != nil {
		t.Fatalf("Issue: unexpected error: %v", err)
	}

	wrongBinding := Binding{Provider: "zalo", PlatformType: "ios", SessionID: "sess-2", DeviceID: "dev-1", Nonce: "nonce-1"}
	wantOTP, err := GenerateReference(challenge.Context, now, DefaultConfig())
	if err != nil {
		t.Fatalf("Generate(challenge.Context): unexpected error: %v", err)
	}
	if err := challenge.Verify(wantOTP, wrongBinding, now.Add(10*time.Second)); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("Verify(binding mismatch) = %v, want ErrBindingMismatch", err)
	}
	if challenge.State() != StateInvalidated {
		t.Fatalf("challenge.State() after binding mismatch = %q, want %q", challenge.State(), StateInvalidated)
	}
}

func TestVerifyGraceExpiryInvalidates(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, _, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if err != nil {
		t.Fatalf("Issue: unexpected error: %v", err)
	}

	if !challenge.IsVisibleExpired(now.Add(60 * time.Second)) {
		t.Fatal("IsVisibleExpired should be true at the 60 second boundary")
	}
	if !challenge.IsGraceExpired(now.Add(90 * time.Second)) {
		t.Fatal("IsGraceExpired should be true at the 90 second boundary")
	}
	wantOTP, err := GenerateReference(challenge.Context, now, DefaultConfig())
	if err != nil {
		t.Fatalf("Generate(challenge.Context): unexpected error: %v", err)
	}
	if err := challenge.Verify(wantOTP, binding, now.Add(90*time.Second)); !errors.Is(err, ErrOTPExpired) {
		t.Fatalf("Verify(expired) = %v, want ErrOTPExpired", err)
	}
	if challenge.State() != StateInvalidated {
		t.Fatalf("challenge.State() after expiry = %q, want %q", challenge.State(), StateInvalidated)
	}
}

func TestIssueRandomUsesRandomMode(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, issuedOTP, err := IssueRandom(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)))
	if err != nil {
		t.Fatalf("IssueRandom: unexpected error: %v", err)
	}

	if challenge.Mode != ModeRandom {
		t.Fatalf("challenge.Mode = %q, want %q", challenge.Mode, ModeRandom)
	}
	if issuedOTP != "aaaa" {
		t.Fatalf("issued OTP = %q, want %q", issuedOTP, "aaaa")
	}
	if challenge.Context == "" {
		t.Fatalf("challenge.Context must be populated with canonical binding context")
	}
}

func TestTimeWindowRollsEveryMinute(t *testing.T) {
	start := time.Unix(1_747_180_800, 0).UTC()
	if TimeWindow(start) == TimeWindow(start.Add(61*time.Second)) {
		t.Fatal("TimeWindow should change after 60 seconds")
	}
}

func TestCooldownEscalation(t *testing.T) {
	cases := []struct {
		sequence int
		want     time.Duration
	}{
		{sequence: 0, want: 0},
		{sequence: 1, want: 60 * time.Second},
		{sequence: 2, want: 5 * time.Minute},
		{sequence: 3, want: 15 * time.Minute},
		{sequence: 4, want: time.Hour},
		{sequence: 99, want: time.Hour},
	}

	for _, testCase := range cases {
		if got := Cooldown(testCase.sequence); got != testCase.want {
			t.Fatalf("Cooldown(%d) = %v, want %v", testCase.sequence, got, testCase.want)
		}
	}
}

func TestMustGenerateSucceeds(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	context := "v:1:1|p:4:zalo|pt:3:web|d:7:web:abc|s:4:x7d9|n:4:p4t2|t:8:29119680"

	otp := MustGenerate(context, now)
	if err := Validate(otp); err != nil {
		t.Fatalf("MustGenerate returned invalid OTP: %v", err)
	}
	if len(otp) != OTPLength {
		t.Fatalf("MustGenerate otp length = %d, want %d", len(otp), OTPLength)
	}
}

func TestMustGenerateRandomSucceeds(t *testing.T) {
	otp := MustGenerateRandom(bytes.NewReader(bytes.Repeat([]byte{0}, OTPLength)))
	if err := Validate(otp); err != nil {
		t.Fatalf("MustGenerateRandom returned invalid OTP: %v", err)
	}
	if otp != "aaaa" {
		t.Fatalf("MustGenerateRandom with zero bytes = %q, want %q", otp, "aaaa")
	}
}

func TestVerifyWithinVisibleWindow(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, _, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if err != nil {
		t.Fatalf("IssueReference: %v", err)
	}

	wantOTP, err := GenerateReference(challenge.Context, now, DefaultConfig())
	if err != nil {
		t.Fatalf("GenerateReference: %v", err)
	}

	// Verify just before visible expiry (59 seconds in)
	verifyAt := now.Add(59 * time.Second)
	if err := challenge.Verify(wantOTP, binding, verifyAt); err != nil {
		t.Fatalf("Verify within visible window: %v", err)
	}
	if challenge.State() != StateVerified {
		t.Fatalf("State after verify = %q, want %q", challenge.State(), StateVerified)
	}
}

func TestVerifyAtVisibleExpiryBoundary(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, _, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if err != nil {
		t.Fatalf("IssueReference: %v", err)
	}

	if !challenge.IsVisibleExpired(now.Add(VisibleExpiry)) {
		t.Fatal("IsVisibleExpired should be true exactly at visible expiry")
	}
}

func TestVerifyInGraceWindowAfterVisibleExpiry(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, _, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if err != nil {
		t.Fatalf("IssueReference: %v", err)
	}

	wantOTP, err := GenerateReference(challenge.Context, now, DefaultConfig())
	if err != nil {
		t.Fatalf("GenerateReference: %v", err)
	}

	// Verify in grace window (between 60-90 seconds): should succeed
	verifyAt := now.Add(75 * time.Second)
	if err := challenge.Verify(wantOTP, binding, verifyAt); err != nil {
		t.Fatalf("Verify in grace window: %v", err)
	}
	if challenge.State() != StateVerified {
		t.Fatalf("State after grace window verify = %q, want %q", challenge.State(), StateVerified)
	}
}

func TestBindingHashImmutable(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, _, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if err != nil {
		t.Fatalf("IssueReference: %v", err)
	}

	originalHash := challenge.BindingHash
	// Verify that hash is immutable
	if len(originalHash) != BindingHashSize {
		t.Fatalf("BindingHash size = %d, want %d", len(originalHash), BindingHashSize)
	}

	// Verify doesn't modify hash
	wantOTP, _ := GenerateReference(challenge.Context, now, DefaultConfig())
	challenge.Verify(wantOTP, binding, now.Add(10*time.Second))
	if !bytes.Equal(originalHash, challenge.BindingHash) {
		t.Fatal("BindingHash should not change after Verify")
	}
}

func TestOTPHashImmutable(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, _, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if err != nil {
		t.Fatalf("IssueReference: %v", err)
	}

	originalHash := challenge.OTPHash
	if len(originalHash) != OTPHashSize {
		t.Fatalf("OTPHash size = %d, want %d", len(originalHash), OTPHashSize)
	}

	wantOTP, _ := GenerateReference(challenge.Context, now, DefaultConfig())
	challenge.Verify(wantOTP, binding, now.Add(10*time.Second))
	if !bytes.Equal(originalHash, challenge.OTPHash) {
		t.Fatal("OTPHash should not change after Verify")
	}
}

func TestVerifyNilChallengeReturnsError(t *testing.T) {
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	var challenge *Challenge
	err := challenge.Verify("aaaa", binding, time.Now())
	if !errors.Is(err, ErrChallengeRequired) {
		t.Fatalf("Verify(nil challenge) = %v, want ErrChallengeRequired", err)
	}
}

func TestStateOfNilChallenge(t *testing.T) {
	var challenge *Challenge
	if challenge.State() != StateInvalidated {
		t.Fatalf("State(nil challenge) = %q, want %q", challenge.State(), StateInvalidated)
	}
}

func TestIsVisibleExpiredNilChallenge(t *testing.T) {
	var challenge *Challenge
	if !challenge.IsVisibleExpired(time.Now()) {
		t.Fatal("IsVisibleExpired(nil challenge) should be true")
	}
}

func TestIsGraceExpiredNilChallenge(t *testing.T) {
	var challenge *Challenge
	if !challenge.IsGraceExpired(time.Now()) {
		t.Fatal("IsGraceExpired(nil challenge) should be true")
	}
}

func TestValidateBindingWithLongValues(t *testing.T) {
	longString := strings.Repeat("x", MaxBindingLength+1)
	binding := Binding{
		Provider:     longString,
		PlatformType: "web",
		SessionID:    "sess-1",
		DeviceID:     "dev-1",
		Nonce:        "nonce-1",
	}

	if err := ValidateBinding(binding); !errors.Is(err, ErrBindingRequired) {
		t.Fatalf("ValidateBinding(long provider) = %v, want ErrBindingRequired", err)
	}
}

func TestValidateBindingWithNonLowercasePlatformType(t *testing.T) {
	binding := Binding{
		Provider:     "zalo",
		PlatformType: "Web",
		SessionID:    "sess-1",
		DeviceID:     "dev-1",
		Nonce:        "nonce-1",
	}

	if err := ValidateBinding(binding); !errors.Is(err, ErrBindingRequired) {
		t.Fatalf("ValidateBinding(uppercase platform) = %v, want ErrBindingRequired", err)
	}
}

func TestValidateBindingWithInvalidPlatformType(t *testing.T) {
	binding := Binding{
		Provider:     "zalo",
		PlatformType: "invalid_platform",
		SessionID:    "sess-1",
		DeviceID:     "dev-1",
		Nonce:        "nonce-1",
	}

	if err := ValidateBinding(binding); !errors.Is(err, ErrBindingRequired) {
		t.Fatalf("ValidateBinding(invalid platform) = %v, want ErrBindingRequired", err)
	}
}

func TestValidAllPlatformTypes(t *testing.T) {
	validPlatforms := []string{"web", "ios", "android", "desktop", "embedded", "other"}

	for _, platform := range validPlatforms {
		binding := Binding{
			Provider:     "zalo",
			PlatformType: platform,
			SessionID:    "sess-1",
			DeviceID:     "dev-1",
			Nonce:        "nonce-1",
		}

		if err := ValidateBinding(binding); err != nil {
			t.Fatalf("ValidateBinding(%s): %v", platform, err)
		}
	}
}

func TestGenerateRandomWithNilReaderReturnsError(t *testing.T) {
	_, err := GenerateRandom(nil)
	if !errors.Is(err, ErrEntropyDepleted) {
		t.Fatalf("GenerateRandom(nil): %v, want ErrEntropyDepleted", err)
	}
}

func TestIssueWithValidBinding(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{
		Provider:     "zalo",
		PlatformType: "web",
		SessionID:    "sess-1",
		DeviceID:     "dev-1",
		Nonce:        "nonce-1",
	}

	challenge, _, err := Issue(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if challenge.Mode != ModeReference {
		t.Fatalf("Issue mode = %q, want %q", challenge.Mode, ModeReference)
	}
	if challenge.IssuedAt != now {
		t.Fatalf("IssuedAt mismatch")
	}
}

func TestVerifyInvalidOTPFormat(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, _, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if err != nil {
		t.Fatalf("IssueReference: %v", err)
	}

	// Try to verify with invalid OTP format
	if err := challenge.Verify("aa", binding, now.Add(10*time.Second)); !errors.Is(err, ErrInvalidOTP) {
		t.Fatalf("Verify(short otp) = %v, want ErrInvalidOTP", err)
	}
	if challenge.State() != StateInvalidated {
		t.Fatalf("State after invalid format = %q, want %q", challenge.State(), StateInvalidated)
	}
}

func TestIsValidHelper(t *testing.T) {
	cases := []struct {
		otp   string
		valid bool
	}{
		{"kqmx", true},
		{"KQMX", true},
		{"abzd", true},
		{"abc", false},
		{"abcde", false},
		{"ab0d", false},
		{"ab1d", false},
	}

	for _, tc := range cases {
		if got := IsValid(tc.otp); got != tc.valid {
			t.Fatalf("IsValid(%q) = %v, want %v", tc.otp, got, tc.valid)
		}
	}
}

func TestCanonicalContextWithTimeBucket(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}

	got, err := CanonicalContextWithTimeBucket(binding, now)
	if err != nil {
		t.Fatalf("CanonicalContextWithTimeBucket: %v", err)
	}

	want, err := CanonicalBindingInput(binding, now)
	if err != nil {
		t.Fatalf("CanonicalBindingInput: %v", err)
	}

	if got != want {
		t.Fatalf("CanonicalContextWithTimeBucket = %q, want %q", got, want)
	}
}

func TestVerifyAfterStateTransitions(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, _, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if err != nil {
		t.Fatalf("IssueReference: %v", err)
	}

	wantOTP, _ := GenerateReference(challenge.Context, now, DefaultConfig())

	// First verify succeeds
	if err := challenge.Verify(wantOTP, binding, now.Add(10*time.Second)); err != nil {
		t.Fatalf("First verify: %v", err)
	}

	// Second verify fails with ErrOTPUsed
	if err := challenge.Verify(wantOTP, binding, now.Add(11*time.Second)); !errors.Is(err, ErrOTPUsed) {
		t.Fatalf("Second verify = %v, want ErrOTPUsed", err)
	}
}

func TestVerifyWithInvalidBindingField(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, _, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if err != nil {
		t.Fatalf("IssueReference: %v", err)
	}

	wantOTP, _ := GenerateReference(challenge.Context, now, DefaultConfig())

	// Try to verify with provider having leading space
	badBinding := Binding{Provider: " zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	if err := challenge.Verify(wantOTP, badBinding, now.Add(10*time.Second)); !errors.Is(err, ErrBindingRequired) {
		t.Fatalf("Verify(bad binding) = %v, want ErrBindingRequired", err)
	}
	if challenge.State() != StateInvalidated {
		t.Fatalf("State after bad binding = %q, want %q", challenge.State(), StateInvalidated)
	}
}

func TestIssueReferenceWithInvalidBinding(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}

	_, _, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if !errors.Is(err, ErrBindingRequired) {
		t.Fatalf("IssueReference(invalid binding) = %v, want ErrBindingRequired", err)
	}
}

func TestIssueRandomWithInvalidBinding(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "INVALID", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}

	_, _, err := IssueRandom(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)))
	if !errors.Is(err, ErrBindingRequired) {
		t.Fatalf("IssueRandom(invalid binding) = %v, want ErrBindingRequired", err)
	}
}

func TestIssueWithNilReaderReturnsError(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}

	_, _, err := Issue(binding, now, nil)
	if !errors.Is(err, ErrEntropyDepleted) {
		t.Fatalf("Issue(nil reader) = %v, want ErrEntropyDepleted", err)
	}
}

func TestIssueReferenceWithNilReaderReturnsError(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}

	_, _, err := IssueReference(binding, now, nil, DefaultConfig())
	if !errors.Is(err, ErrEntropyDepleted) {
		t.Fatalf("IssueReference(nil reader) = %v, want ErrEntropyDepleted", err)
	}
}

func TestIssueRandomWithNilReaderReturnsError(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}

	_, _, err := IssueRandom(binding, now, nil)
	if !errors.Is(err, ErrEntropyDepleted) {
		t.Fatalf("IssueRandom(nil reader) = %v, want ErrEntropyDepleted", err)
	}
}

func TestVerifyWithContextValidationFailure(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, _, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if err != nil {
		t.Fatalf("IssueReference: %v", err)
	}

	wantOTP, _ := GenerateReference(challenge.Context, now, DefaultConfig())

	// Try to verify with empty provider (which will fail ValidateBinding)
	badBinding := Binding{Provider: "", PlatformType: "web", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	if err := challenge.Verify(wantOTP, badBinding, now.Add(10*time.Second)); !errors.Is(err, ErrBindingRequired) {
		t.Fatalf("Verify(bad binding field) = %v, want ErrBindingRequired", err)
	}
}

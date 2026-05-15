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
	context := "provider:zalo|device:web:abc123|session:x7d9|nonce:p4t2"

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
	context := "provider:zalo|device:web:abc123|session:x7d9|nonce:p4t2"
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
	if err := Validate("kqmx"); err != nil {
		t.Fatalf("Validate(valid): unexpected error: %v", err)
	}
	if err := Validate("KQMX"); err != nil {
		t.Fatalf("Validate(uppercase valid): unexpected error: %v", err)
	}

	for _, value := range []string{"abc", "abcde", "ab1d", "AB1D"} {
		if err := Validate(value); !errors.Is(err, ErrInvalidOTP) {
			t.Fatalf("Validate(%q) = %v, want ErrInvalidOTP", value, err)
		}
	}
}

func TestCanonicalBindingInput(t *testing.T) {
	binding := Binding{Provider: "zalo", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}

	got, err := CanonicalBindingInput(binding)
	if err != nil {
		t.Fatalf("CanonicalBindingInput: unexpected error: %v", err)
	}

	want := "v1|4:zalo|5:dev-1|6:sess-1|7:nonce-1"
	if got != want {
		t.Fatalf("CanonicalBindingInput = %q, want %q", got, want)
	}
}

func TestCanonicalReferenceInputUsesTimeWindow(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	got, err := CanonicalReferenceInput("provider:zalo|device:web:abc123|session:x7d9|nonce:p4t2", now)
	if err != nil {
		t.Fatalf("CanonicalReferenceInput: unexpected error: %v", err)
	}

	// Hardened spec: v1|<len>:<context>|<len>:<time_bucket>
	want := "v1|55:provider:zalo|device:web:abc123|session:x7d9|nonce:p4t2|8:29119680"
	if got != want {
		t.Fatalf("CanonicalReferenceInput = %q, want %q", got, want)
	}
}

func TestIssueAndVerifySuccess(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if err != nil {
		t.Fatalf("Issue: unexpected error: %v", err)
	}

	if challenge.ID != strings.Repeat("A", ChallengeIDLength) {
		t.Fatalf("challenge.ID = %q, want %q", challenge.ID, strings.Repeat("A", ChallengeIDLength))
	}
	if challenge.Mode != ModeReference {
		t.Fatalf("challenge.Mode = %q, want %q", challenge.Mode, ModeReference)
	}
	if challenge.Context != "v1|4:zalo|5:dev-1|6:sess-1|7:nonce-1" {
		t.Fatalf("challenge.Context = %q, want canonical binding context", challenge.Context)
	}
	wantOTP, err := GenerateReference(challenge.Context, now, DefaultConfig())
	if err != nil {
		t.Fatalf("Generate(challenge.Context): unexpected error: %v", err)
	}
	if challenge.OTP != wantOTP {
		t.Fatalf("challenge.OTP = %q, want %q", challenge.OTP, wantOTP)
	}
	if challenge.State() != StatePending {
		t.Fatalf("challenge.State() = %q, want %q", challenge.State(), StatePending)
	}

	verifyAt := now.Add(75 * time.Second)
	if err := challenge.Verify(strings.ToUpper(wantOTP), binding, verifyAt); err != nil {
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
	binding := Binding{Provider: "zalo", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
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
	binding := Binding{Provider: "zalo", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if err != nil {
		t.Fatalf("Issue: unexpected error: %v", err)
	}

	wrongBinding := Binding{Provider: "zalo", SessionID: "sess-2", DeviceID: "dev-1", Nonce: "nonce-1"}
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
	binding := Binding{Provider: "zalo", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
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
	if err := challenge.Verify(strings.ToUpper(wantOTP), binding, now.Add(90*time.Second)); !errors.Is(err, ErrOTPExpired) {
		t.Fatalf("Verify(expired) = %v, want ErrOTPExpired", err)
	}
	if challenge.State() != StateInvalidated {
		t.Fatalf("challenge.State() after expiry = %q, want %q", challenge.State(), StateInvalidated)
	}
}

func TestIssueRandomUsesRandomMode(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", SessionID: "sess-1", DeviceID: "dev-1", Nonce: "nonce-1"}
	challenge, err := IssueRandom(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)))
	if err != nil {
		t.Fatalf("IssueRandom: unexpected error: %v", err)
	}

	if challenge.Mode != ModeRandom {
		t.Fatalf("challenge.Mode = %q, want %q", challenge.Mode, ModeRandom)
	}
	if challenge.OTP != "aaaa" {
		t.Fatalf("challenge.OTP = %q, want %q", challenge.OTP, "aaaa")
	}
	if challenge.Context != "" {
		t.Fatalf("challenge.Context = %q, want empty string", challenge.Context)
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

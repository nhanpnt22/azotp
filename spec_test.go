package azotp

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestDefaultConfigUsesDevelopmentSecret(t *testing.T) {
	config := DefaultConfig()
	if config.ServerSecret != DefaultSecret {
		t.Fatalf("DefaultConfig().ServerSecret = %q, want %q", config.ServerSecret, DefaultSecret)
	}
}

func TestValidateContextRejectsWhitespaceAndEmpty(t *testing.T) {
	for _, context := range []string{"", " leading", "trailing ", " both "} {
		if err := ValidateContext(context); !errors.Is(err, ErrContextRequired) {
			t.Fatalf("ValidateContext(%q) = %v, want ErrContextRequired", context, err)
		}
	}
}

func TestValidateBindingRequiresProviderDeviceSessionNonce(t *testing.T) {
	cases := []Binding{
		{},
		{Provider: "zalo"},
		{Provider: "zalo", PlatformType: "web", DeviceID: "dev-1"},
		{Provider: "zalo", PlatformType: "web", DeviceID: "dev-1", SessionID: "sess-1"},
	}

	for _, binding := range cases {
		if err := ValidateBinding(binding); !errors.Is(err, ErrBindingRequired) {
			t.Fatalf("ValidateBinding(%+v) = %v, want ErrBindingRequired", binding, err)
		}
	}
}

func TestIssueWrapperUsesDefaultConfig(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{Provider: "zalo", PlatformType: "web", DeviceID: "device-abc123", SessionID: "sess-x7d9", Nonce: "nonce-p4t2"}
	challenge, otp, err := Issue(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)))
	if err != nil {
		t.Fatalf("Issue: unexpected error: %v", err)
	}

	want, err := GenerateReference(challenge.Context, now, DefaultConfig())
	if err != nil {
		t.Fatalf("GenerateReference: unexpected error: %v", err)
	}
	if otp != want {
		t.Fatalf("Issue() OTP = %q, want %q", otp, want)
	}
}

func TestGenerateReferenceFallsBackToDefaultSecret(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	context := "v:1:1|p:4:zalo|pt:3:web|d:7:web:abc|s:4:x7d9|n:4:p4t2|t:8:29119680"
	got, err := GenerateReference(context, now, Config{})
	if err != nil {
		t.Fatalf("GenerateReference: unexpected error: %v", err)
	}
	want, err := GenerateWithSecret(context, DefaultSecret, now)
	if err != nil {
		t.Fatalf("GenerateWithSecret: unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("GenerateReference(default config) = %q, want %q", got, want)
	}
}

package azotp

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type vectorFile struct {
	Vectors []vector `json:"vectors"`
}

type vector struct {
	ID               string `json:"id"`
	Type             string `json:"type"`
	CanonicalContext string `json:"canonical_context"`
	Input            struct {
		ServerSecret string `json:"server_secret"`
		Provider     string `json:"provider"`
		PlatformType string `json:"platform_type"`
		DeviceID     string `json:"device_id"`
		SessionID    string `json:"session_id"`
		Nonce        string `json:"nonce"`
		TimeBucket   int64  `json:"time_bucket"`
	} `json:"input"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()

	raw, err := os.ReadFile("docs/tests/azotp_test_vectors.json")
	if err != nil {
		t.Fatalf("ReadFile(vectors): %v", err)
	}

	var file vectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("Unmarshal(vectors): %v", err)
	}

	if len(file.Vectors) == 0 {
		t.Fatal("expected at least one test vector")
	}

	return file.Vectors
}

func TestVectorsCanonicalizationAndDeterminism(t *testing.T) {
	vectors := loadVectors(t)
	computed := map[string]string{}

	for _, item := range vectors {
		if item.Type != "reference" {
			continue
		}

		now := time.Unix(item.Input.TimeBucket*60, 0).UTC()
		binding := Binding{
			Provider:     item.Input.Provider,
			PlatformType: item.Input.PlatformType,
			DeviceID:     item.Input.DeviceID,
			SessionID:    item.Input.SessionID,
			Nonce:        item.Input.Nonce,
		}

		context, err := CanonicalBindingInput(binding, now)
		if err != nil {
			t.Fatalf("%s: CanonicalBindingInput: %v", item.ID, err)
		}
		if context != item.CanonicalContext {
			t.Fatalf("%s: canonical mismatch: got %q want %q", item.ID, context, item.CanonicalContext)
		}

		left, err := GenerateWithSecret(context, item.Input.ServerSecret, now)
		if err != nil {
			t.Fatalf("%s: GenerateWithSecret(left): %v", item.ID, err)
		}
		right, err := GenerateWithSecret(context, item.Input.ServerSecret, now)
		if err != nil {
			t.Fatalf("%s: GenerateWithSecret(right): %v", item.ID, err)
		}
		if left != right {
			t.Fatalf("%s: deterministic output mismatch: %q != %q", item.ID, left, right)
		}
		if err := Validate(left); err != nil {
			t.Fatalf("%s: generated otp invalid: %v", item.ID, err)
		}

		computed[item.ID] = left
	}

	if computed["V001"] == computed["V002"] {
		t.Fatal("V001/V002 should produce different OTPs for different nonce")
	}
	if computed["V001"] == computed["V003"] {
		t.Fatal("V001/V003 should produce different OTPs for different platform_type")
	}
	if computed["V001"] == computed["V004"] {
		t.Fatal("V001/V004 should produce different OTPs for different time_bucket")
	}
}

func TestIssueStoresFixedHashSizes(t *testing.T) {
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := Binding{
		Provider:     "zalo",
		PlatformType: "web",
		DeviceID:     "dev-1",
		SessionID:    "sess-1",
		Nonce:        "nonce-1",
	}

	ref, err := IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), DefaultConfig())
	if err != nil {
		t.Fatalf("IssueReference: %v", err)
	}
	if len(ref.OTPHash) != OTPHashSize {
		t.Fatalf("IssueReference OTPHash len=%d want=%d", len(ref.OTPHash), OTPHashSize)
	}
	if len(ref.BindingHash) != BindingHashSize {
		t.Fatalf("IssueReference BindingHash len=%d want=%d", len(ref.BindingHash), BindingHashSize)
	}

	rand, err := IssueRandom(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)))
	if err != nil {
		t.Fatalf("IssueRandom: %v", err)
	}
	if len(rand.OTPHash) != OTPHashSize {
		t.Fatalf("IssueRandom OTPHash len=%d want=%d", len(rand.OTPHash), OTPHashSize)
	}
	if len(rand.BindingHash) != BindingHashSize {
		t.Fatalf("IssueRandom BindingHash len=%d want=%d", len(rand.BindingHash), BindingHashSize)
	}
}

func TestValidateBindingPlatformTypeRules(t *testing.T) {
	base := Binding{
		Provider:     "zalo",
		PlatformType: "web",
		DeviceID:     "dev-1",
		SessionID:    "sess-1",
		Nonce:        "nonce-1",
	}

	if err := ValidateBinding(base); err != nil {
		t.Fatalf("ValidateBinding(base): %v", err)
	}

	invalid := []string{"", "WEB", "tvos", " web", "web "}
	for _, pt := range invalid {
		binding := base
		binding.PlatformType = pt
		if err := ValidateBinding(binding); err == nil {
			t.Fatalf("ValidateBinding(platform_type=%q) expected error", pt)
		}
	}
}

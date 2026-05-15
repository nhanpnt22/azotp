package azotp_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nhanpnt22/azotp"
)

func TestReferenceModeExample(t *testing.T) {
	output := runExample(t, "./examples/reference-mode", map[string]string{"AZOTP_SERVER_SECRET": "custom-secret"})
	if !strings.Contains(output, "mode: reference") {
		t.Fatalf("reference-mode output missing mode: reference\n%s", output)
	}
	if !strings.Contains(output, "secret: custom-secret") {
		t.Fatalf("reference-mode output missing configured secret\n%s", output)
	}
	if !strings.Contains(output, "otp: "+expectedOTP(t, azotp.Config{ServerSecret: "custom-secret"})) {
		t.Fatalf("reference-mode output missing expected OTP\n%s", output)
	}
}

func TestServiceWrapperExample(t *testing.T) {
	output := runExample(t, "./examples/service-wrapper", map[string]string{"AZOTP_SERVER_SECRET": "custom-secret"})
	if !strings.Contains(output, "mode: reference") {
		t.Fatalf("service-wrapper output missing mode: reference\n%s", output)
	}
	if !strings.Contains(output, "secret: cu***********") {
		t.Fatalf("service-wrapper output missing redacted secret\n%s", output)
	}
	if !strings.Contains(output, "otp: "+expectedOTP(t, azotp.Config{ServerSecret: "custom-secret"})) {
		t.Fatalf("service-wrapper output missing expected OTP\n%s", output)
	}
}

func runExample(t *testing.T, examplePath string, extraEnv map[string]string) string {
	t.Helper()

	moduleDir := filepath.Clean(".")
	cmd := exec.Command("go", "run", examplePath)
	cmd.Dir = moduleDir
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "GO111MODULE=on")
	for key, value := range extraEnv {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout

	if err := cmd.Run(); err != nil {
		t.Fatalf("go run %s failed: %v\n%s", examplePath, err, stdout.String())
	}

	return stdout.String()
}

func expectedOTP(t *testing.T, config azotp.Config) string {
	t.Helper()

	now := time.Unix(1_747_180_800, 0).UTC()
	binding := azotp.Binding{Provider: "zalo", PlatformType: "web", DeviceID: "device-abc123", SessionID: "sess-x7d9", Nonce: "nonce-p4t2"}
	context, err := azotp.CanonicalBindingInput(binding, now)
	if err != nil {
		t.Fatalf("CanonicalBindingInput: unexpected error: %v", err)
	}
	otp, err := azotp.GenerateReference(context, now, config)
	if err != nil {
		t.Fatalf("GenerateReference: unexpected error: %v", err)
	}
	return otp
}

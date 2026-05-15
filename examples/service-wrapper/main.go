package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nhanpnt22/azotp"
)

func main() {
	config := loadConfigFromEnvironment()
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := azotp.Binding{
		Provider:     "zalo",
		PlatformType: "web",
		SessionID:    "sess-x7d9",
		DeviceID:     "device-abc123",
		Nonce:        "nonce-p4t2",
	}

	challenge, err := issueChallenge(config, binding, now)
	if err != nil {
		panic(err)
	}

	fmt.Println("mode:", challenge.Mode)
	fmt.Println("secret:", redactSecret(config.ServerSecret))
	fmt.Println("challenge_id:", challenge.ID)
	fmt.Println("otp:", strings.ToUpper(challenge.OTP))
	fmt.Println("visible_expires_at:", challenge.VisibleExpiresAt.Format(time.RFC3339))
	fmt.Println("grace_expires_at:", challenge.GraceExpiresAt.Format(time.RFC3339))
}

func loadConfigFromEnvironment() azotp.Config {
	secret := strings.TrimSpace(os.Getenv("AZOTP_SERVER_SECRET"))
	if secret == "" {
		secret = azotp.DefaultSecret
	}

	return azotp.Config{ServerSecret: secret}
}

func issueChallenge(config azotp.Config, binding azotp.Binding, now time.Time) (*azotp.Challenge, error) {
	return azotp.IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), config)
}

func redactSecret(secret string) string {
	if secret == "" {
		return "<empty>"
	}
	if len(secret) <= 2 {
		return "**"
	}
	return secret[:2] + strings.Repeat("*", len(secret)-2)
}

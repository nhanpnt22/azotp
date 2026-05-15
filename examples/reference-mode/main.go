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
	config := loadConfig()
	now := time.Unix(1_747_180_800, 0).UTC()
	binding := azotp.Binding{
		Provider:  "zalo",
		SessionID: "sess-x7d9",
		DeviceID:  "device-abc123",
		Nonce:     "nonce-p4t2",
	}

	challenge, err := azotp.IssueReference(binding, now, bytes.NewReader(bytes.Repeat([]byte{0}, 20)), config)
	if err != nil {
		panic(err)
	}

	context, err := azotp.CanonicalBindingInput(binding)
	if err != nil {
		panic(err)
	}

	otp, err := azotp.GenerateReference(context, now, config)
	if err != nil {
		panic(err)
	}

	fmt.Println("mode:", challenge.Mode)
	fmt.Println("secret:", config.ServerSecret)
	fmt.Println("challenge_id:", challenge.ID)
	fmt.Println("otp:", strings.ToUpper(otp))
	fmt.Println("visible_expires_at:", challenge.VisibleExpiresAt.Format(time.RFC3339))
	fmt.Println("grace_expires_at:", challenge.GraceExpiresAt.Format(time.RFC3339))
}

func loadConfig() azotp.Config {
	secret := strings.TrimSpace(os.Getenv("AZOTP_SERVER_SECRET"))
	if secret == "" {
		secret = azotp.DefaultSecret
	}

	return azotp.Config{ServerSecret: secret}
}

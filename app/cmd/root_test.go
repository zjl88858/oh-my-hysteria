// SPDX-License-Identifier: MIT-0

package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestForkIdentity(t *testing.T) {
	if rootCmd.Use != "oh-my-hysteria" {
		t.Fatalf("unexpected command name: %q", rootCmd.Use)
	}
	version, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	if appVersion != strings.TrimSpace(string(version)) {
		t.Fatalf("Go version %q differs from VERSION %q", appVersion, version)
	}
	if !strings.Contains(appAboutLong, appName) || !strings.Contains(appAboutLong, appVersion) {
		t.Fatalf("missing fork identity in version output: %q", appAboutLong)
	}
}

func TestForkEnvironment(t *testing.T) {
	for _, suffix := range []string{"LOG_LEVEL", "LOG_FORMAT", "ACME_DIR"} {
		t.Run(suffix, func(t *testing.T) {
			key := "OH_MY_HYSTERIA_" + suffix
			legacyKey := "HYSTERIA_" + suffix
			t.Setenv(key, "")
			t.Setenv(legacyKey, "")
			if got := envOrDefaultString(key, "default"); got != "default" {
				t.Fatalf("unexpected default: %q", got)
			}
			t.Setenv(legacyKey, "legacy")
			if got := envOrDefaultString(key, "default"); got != "legacy" {
				t.Fatalf("legacy fallback not used: %q", got)
			}
			t.Setenv(key, "fork")
			if got := envOrDefaultString(key, "default"); got != "fork" {
				t.Fatalf("fork variable must take precedence: %q", got)
			}
		})
	}
}

func TestForkUpdateStatus(t *testing.T) {
	var output bytes.Buffer
	checkUpdateCmd.SetOut(&output)
	defer checkUpdateCmd.SetOut(nil)
	if err := checkUpdateCmd.RunE(checkUpdateCmd, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "upstream update checks are disabled") {
		t.Fatalf("unexpected update status: %q", output.String())
	}
}

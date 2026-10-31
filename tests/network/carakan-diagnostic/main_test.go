// SPDX-License-Identifier: MIT-0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiagnosticEndpointLoopback(t *testing.T) {
	for _, h := range []float64{2, 1.5} {
		t.Run(fmt.Sprint(h), func(t *testing.T) {
			dir := t.TempDir()
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
				NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			keyDER, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := config{
				Role: "server", Address: "127.0.0.1:0", Password: "public-test-only-diagnostic-password-32+", Auth: "test-auth-only", Cert: certPath, Key: keyPath,
				ServerName: "localhost", Output: filepath.Join(dir, "server.json"), Entropy: h, Bytes: 4096, LifetimeSeconds: 1,
			}
			done := make(chan error, 1)
			go func() { _, err := run(cfg); done <- err }()
			var ready struct{ Address string }
			deadline := time.Now().Add(2 * time.Second)
			for {
				data, err := os.ReadFile(cfg.Output + ".ready")
				if err == nil {
					if err := json.Unmarshal(data, &ready); err != nil {
						t.Fatal(err)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("diagnostic server readiness timeout")
				}
				time.Sleep(5 * time.Millisecond)
			}
			clientCfg := cfg
			clientCfg.Role, clientCfg.Address, clientCfg.CA, clientCfg.Output = "client", ready.Address, certPath, filepath.Join(dir, "client.json")
			if status, err := run(clientCfg); err != nil || status != 0 {
				t.Fatalf("client status=%d err=%v", status, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			var clientRecord, serverRecord record
			for name, target := range map[string]*record{"client.json": &clientRecord, "server.json": &serverRecord} {
				data, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(data, target); err != nil {
					t.Fatal(err)
				}
				if target.TraceOverflows != 0 || target.PayloadsOrSecretsRecorded || !target.NormalTLS || target.Stats.AuthDrops != 0 {
					t.Fatalf("bad trace %s", name)
				}
			}
			if !clientRecord.Complete || !serverRecord.Connected || clientRecord.ApplicationSent != 4096 || clientRecord.ApplicationReceived != 4096 {
				t.Fatal("incomplete normal-TLS transfer")
			}
			// Every outer packet read must have a matching sender fingerprint.
			for _, pair := range [][2]record{{clientRecord, serverRecord}, {serverRecord, clientRecord}} {
				sent := make(map[string]bool)
				for _, e := range pair[0].Events {
					if e.Layer == "outer" && e.Op == "write" && e.Error == "" {
						sent[e.Digest] = true
					}
				}
				for _, e := range pair[1].Events {
					if e.Layer == "outer" && e.Op == "read" && !sent[e.Digest] {
						t.Fatal("unmatched received fingerprint")
					}
				}
			}
		})
	}
}

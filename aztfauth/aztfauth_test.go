package aztfauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGetClientCert_ParsesLegacyAndModernPFX(t *testing.T) {
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatalf("openssl is not available on PATH: %v", err)
	}

	const password = "Pa55w0rd123"

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "service-principal.key")
	certPath := filepath.Join(dir, "service-principal.crt")
	writeSelfSignedCertAndKey(t, keyPath, certPath)

	legacyPFX := filepath.Join(dir, "legacy.pfx")
	modernPFX := filepath.Join(dir, "modern.pfx")

	runOpenSSL(t, opensslPath,
		"pkcs12", "-export",
		"-certpbe", "PBE-SHA1-3DES",
		"-keypbe", "PBE-SHA1-3DES",
		"-macalg", "sha1",
		"-out", legacyPFX,
		"-inkey", keyPath,
		"-in", certPath,
		"-passout", "pass:"+password,
	)

	runOpenSSL(t, opensslPath,
		"pkcs12", "-export",
		"-macalg", "sha256",
		"-out", modernPFX,
		"-inkey", keyPath,
		"-in", certPath,
		"-passout", "pass:"+password,
	)

	t.Run("legacy pfx", func(t *testing.T) {
		opt := Option{ClientCertPfxFile: legacyPFX, ClientCertPassword: []byte(password)}
		certs, key, err := opt.getClientCert()
		if err != nil {
			t.Fatalf("expected legacy PFX to parse, got error: %v", err)
		}
		if len(certs) == 0 || key == nil {
			t.Fatalf("expected certificate and private key from legacy PFX, got certs=%d key=%v", len(certs), key)
		}
	})

	t.Run("modern pfx", func(t *testing.T) {
		opt := Option{ClientCertPfxFile: modernPFX, ClientCertPassword: []byte(password)}
		certs, key, err := opt.getClientCert()
		if err != nil {
			t.Fatalf("expected modern PFX to parse, got error: %v", err)
		}
		if len(certs) == 0 || key == nil {
			t.Fatalf("expected certificate and private key from modern PFX, got certs=%d key=%v", len(certs), key)
		}
	})
}

func writeSelfSignedCertAndKey(t *testing.T, keyPath, certPath string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "entrauth-pfx-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key PEM: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing cert PEM: %v", err)
	}
}

func runOpenSSL(t *testing.T, opensslPath string, args ...string) {
	t.Helper()
	cmd := exec.Command(opensslPath, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
}

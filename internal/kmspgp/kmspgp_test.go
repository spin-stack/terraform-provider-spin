package kmspgp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// fakeKMS is KMS with the private key here: a test's, signing as KMS's RSASSA_PKCS1_V1_5_SHA_256
// does over a digest it is given.
type fakeKMS struct {
	key   *rsa.PrivateKey
	signs int
	fail  error
}

func (f *fakeKMS) Sign(_ context.Context, _ string, digest []byte) ([]byte, error) {
	f.signs++
	if f.fail != nil {
		return nil, f.fail
	}
	return rsa.SignPKCS1v15(nil, f.key, crypto.SHA256, digest)
}

func (f *fakeKMS) PublicKey(context.Context, string) (*rsa.PublicKey, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	return &f.key.PublicKey, nil
}

var testKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

func key(t *testing.T, f *fakeKMS) Key {
	t.Helper()
	s, err := NewKMSSigner(t.Context(), f, "alias/test")
	if err != nil {
		t.Fatal(err)
	}
	k, err := New(s, Created)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func public(t *testing.T, k Key) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := k.WritePublic(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// What KMS signs is a signature anybody holding the public key checks, over these bytes and no
// others: the registries' check of a release.
func TestASignatureChecksAgainstThePublicKey(t *testing.T) {
	f := &fakeKMS{key: testKey}
	k := key(t, f)
	sums := []byte("e3b0c442  terraform-provider-spin_0.1.0_linux_amd64.zip\n")
	var sig bytes.Buffer
	at := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := k.Sign(&sig, bytes.NewReader(sums), at); err != nil {
		t.Fatal(err)
	}
	// Signed when the release was, not when the key was made.
	p, err := packet.Read(bytes.NewReader(sig.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := p.(*packet.Signature); !ok || !s.CreationTime.Equal(at) {
		t.Fatalf("the signature is %T made %v, want one made %v", p, s.CreationTime, at)
	}
	ring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(public(t, k)))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := openpgp.CheckDetachedSignature(ring, bytes.NewReader(sums), bytes.NewReader(sig.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := signer.Identities[UserID]; !ok {
		t.Fatalf("signed by %v", signer.Identities)
	}
	if _, err := openpgp.CheckDetachedSignature(ring, strings.NewReader("other bytes"), bytes.NewReader(sig.Bytes()), nil); err == nil {
		t.Fatal("the signature checks over other bytes")
	}
}

// GnuPG, which is what the registries' instructions verify with, takes the key and the signature:
// the format is OpenPGP's, not this package's idea of it.
func TestGnuPGVerifiesTheSignature(t *testing.T) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("no gpg on PATH")
	}
	k := key(t, &fakeKMS{key: testKey})
	home := t.TempDir()
	dir := t.TempDir()
	sums := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sums, []byte("sums\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(sums + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(sums)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Sign(f, in, time.Now()); err != nil {
		t.Fatal(err)
	}
	_ = in.Close()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	imp := exec.Command(gpg, "--homedir", home, "--batch", "--import")
	imp.Stdin = bytes.NewReader(public(t, k))
	if out, err := imp.CombinedOutput(); err != nil {
		t.Fatalf("gpg --import: %v: %s", err, out)
	}
	if out, err := exec.Command(gpg, "--homedir", home, "--batch", "--verify", sums+".sig", sums).CombinedOutput(); err != nil ||
		!strings.Contains(string(out), "Good signature from \""+UserID+"\"") {
		t.Fatalf("gpg --verify: %v: %s", err, out)
	}
	if err := os.WriteFile(sums, []byte("other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(gpg, "--homedir", home, "--batch", "--verify", sums+".sig", sums).CombinedOutput(); err == nil {
		t.Fatalf("gpg verified other bytes: %s", out)
	}
}

// The same KMS key and creation time are the same OpenPGP key, byte for byte: what a registry was
// given once is what every release after is checked against. Another time is another key.
func TestTheKeyIsItsKMSKeyAndTime(t *testing.T) {
	a, b := key(t, &fakeKMS{key: testKey}), key(t, &fakeKMS{key: testKey})
	if !bytes.Equal(public(t, a), public(t, b)) || a.Fingerprint() != b.Fingerprint() || len(a.Fingerprint()) != 40 {
		t.Fatalf("fingerprints %s and %s", a.Fingerprint(), b.Fingerprint())
	}
	// A version 4 key and self-signature: what Terraform's OpenPGP reads, which knows no later one.
	ring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(public(t, a)))
	if err != nil {
		t.Fatal(err)
	}
	if e := ring[0]; e.PrimaryKey.Version != 4 || e.Identities[UserID].SelfSignature.Version != 4 {
		t.Fatalf("key version %d, self-signature version %d", e.PrimaryKey.Version, e.Identities[UserID].SelfSignature.Version)
	}
	s, err := NewKMSSigner(t.Context(), &fakeKMS{key: testKey}, "alias/test")
	if err != nil {
		t.Fatal(err)
	}
	later, err := New(s, Created.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if later.Fingerprint() == a.Fingerprint() {
		t.Fatal("another creation time is the same key")
	}
}

// What KMS refuses, and what is not RSA over SHA-256, signs nothing.
func TestWhatKMSCannotSignIsRefused(t *testing.T) {
	if _, err := NewKMSSigner(t.Context(), &fakeKMS{key: testKey, fail: errors.New("AccessDenied")}, "alias/test"); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("err = %v", err)
	}
	f := &fakeKMS{key: testKey}
	k := key(t, f)
	f.fail = errors.New("throttled")
	if err := k.Sign(&bytes.Buffer{}, strings.NewReader("x"), time.Now()); err == nil || !strings.Contains(err.Error(), "throttled") {
		t.Fatalf("err = %v", err)
	}
	s, err := NewKMSSigner(t.Context(), &fakeKMS{key: testKey}, "alias/test")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("x"))
	if _, err := s.Sign(nil, sum[:], crypto.SHA512); err == nil {
		t.Fatal("signed as SHA-512, which KMS is not asked for")
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(ec, Created); err == nil || !strings.Contains(err.Error(), "RSA") {
		t.Fatalf("an ECDSA key: %v", err)
	}
}

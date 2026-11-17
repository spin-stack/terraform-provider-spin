package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/spin-stack/terraform-provider-spin/internal/kmspgp"
)

type localKMS struct{ key *rsa.PrivateKey }

func (l localKMS) Sign(_ context.Context, _ string, digest []byte) ([]byte, error) {
	return rsa.SignPKCS1v15(nil, l.key, crypto.SHA256, digest)
}

func (l localKMS) PublicKey(context.Context, string) (*rsa.PublicKey, error) {
	return &l.key.PublicKey, nil
}

// The public key is printed for the registries, and a file signed with it is checked by it.
func TestThePublicKeySignsAndChecks(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	connect := func(context.Context) (kmspgp.KMS, error) { return localKMS{k}, nil }
	var pub bytes.Buffer
	if err := run(t.Context(), []string{"-key", "alias/k", "public"}, &pub, connect); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pub.String(), "# "+kmspgp.UserID+", fingerprint ") || !strings.Contains(pub.String(), "BEGIN PGP PUBLIC KEY BLOCK") {
		t.Fatalf("printed %s", pub.String())
	}
	dir := t.TempDir()
	sums := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sums, []byte("sums\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(t.Context(), []string{"-key", "alias/k", "sign", "-out", sums + ".sig", sums}, &bytes.Buffer{}, connect); err != nil {
		t.Fatal(err)
	}
	ring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(pub.String()[strings.Index(pub.String(), "-----BEGIN"):]))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(sums + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openpgp.CheckDetachedSignature(ring, strings.NewReader("sums\n"), bytes.NewReader(sig), nil); err != nil {
		t.Fatal(err)
	}
}

// What is not a whole command signs nothing and says so.
func TestAnIncompleteCommandIsRefused(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	connect := func(context.Context) (kmspgp.KMS, error) { return localKMS{k}, nil }
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"no key":                  {"public"},
		"no verb":                 {"-key", "alias/k"},
		"another verb":            {"-key", "alias/k", "verify"},
		"no out":                  {"-key", "alias/k", "sign", file},
		"no file":                 {"-key", "alias/k", "sign", "-out", file + ".sig"},
		"a missing file":          {"-key", "alias/k", "sign", "-out", file + ".sig", file + ".none"},
		"no such flag":            {"-nope"},
		"a bad sign flag":         {"-key", "alias/k", "sign", "-nope"},
		"an unwritable signature": {"-key", "alias/k", "sign", "-out", filepath.Join(file, "x.sig"), file},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(t.Context(), args, &bytes.Buffer{}, connect); err == nil {
				t.Fatal("ran")
			}
		})
	}
	if err := run(t.Context(), []string{"-key", "alias/k", "public"}, &bytes.Buffer{}, func(context.Context) (kmspgp.KMS, error) {
		return nil, errors.New("no credentials")
	}); err == nil || !strings.Contains(err.Error(), "no credentials") {
		t.Fatalf("err = %v", err)
	}
}

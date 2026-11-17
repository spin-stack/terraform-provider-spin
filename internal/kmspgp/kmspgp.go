// Package kmspgp is an OpenPGP key whose private half is a KMS key: the Terraform and OpenTofu
// registries take a provider's release only when an OpenPGP key they hold signs its SHA256SUMS,
// and spin-stack keeps no private key anywhere but KMS (spin-stack/ci's signing.tf).
//
// The key is the KMS key's RSA public key and a creation time, and its user id is self-signed by
// KMS: the same KMS key and the same time are always the same OpenPGP key - its fingerprint, its
// armour byte for byte - so the public key a registry was given once is the one every release is
// checked against.
package kmspgp

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Created is when the key is said to have been made: part of its fingerprint, so never moved.
var Created = time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)

// Who the key says it is: UserID, as OpenPGP spells a name and a comment.
const (
	name    = "spin-stack"
	comment = "terraform-provider-spin releases"
	UserID  = name + " (" + comment + ")"
)

// Signer is the RSA key that signs: KMS's, or a test's.
type Signer interface {
	crypto.Signer
}

// Key is the OpenPGP key of signer.
type Key struct {
	entity *openpgp.Entity
	config *packet.Config
}

// New is signer's OpenPGP key, created at created, its user id self-signed by signer.
func New(signer Signer, created time.Time) (Key, error) {
	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		return Key{}, fmt.Errorf("kmspgp: the key is %T, and the registries take RSA", signer.Public())
	}
	// No salt notation: go-crypto salts v4 signatures by default, which guards EdDSA against faults
	// and does nothing for RSA PKCS#1 v1.5, and would make the self-signature - so the public key a
	// registry holds - another each time it is printed.
	deterministic := false
	cfg := &packet.Config{DefaultHash: crypto.SHA256, Time: func() time.Time { return created }, NonDeterministicSignaturesViaNotation: &deterministic}
	primary := packet.NewRSAPublicKey(created, pub)
	// Built here, not by packet.NewSignerPrivateKey, which takes a key it holds and no other: what
	// signs is priv.PrivateKey as a crypto.Signer, which KMS's is.
	priv := &packet.PrivateKey{PublicKey: *primary, PrivateKey: signer}
	uid := packet.NewUserId(name, comment, "")
	if uid == nil {
		return Key{}, errors.New("kmspgp: the user id is not one")
	}
	primaryID := true
	self := &packet.Signature{
		Version:      4, // mutate-exempt: go-crypto signs with the key's own version, and the test holds it to 4
		SigType:      packet.SigTypePositiveCert,
		PubKeyAlgo:   packet.PubKeyAlgoRSA,
		Hash:         crypto.SHA256,
		CreationTime: created,
		IssuerKeyId:  &primary.KeyId,
		IsPrimaryId:  &primaryID,
		FlagsValid:   true,
		FlagSign:     true,
		FlagCertify:  true,
	}
	if err := self.SignUserId(uid.Id, primary, priv, cfg); err != nil {
		return Key{}, fmt.Errorf("kmspgp: self-signing the user id: %w", err)
	}
	e := &openpgp.Entity{
		PrimaryKey: primary,
		PrivateKey: priv,
		Identities: map[string]*openpgp.Identity{uid.Id: {
			Name: uid.Id, UserId: uid, SelfSignature: self, Signatures: []*packet.Signature{self},
		}},
	}
	return Key{entity: e, config: cfg}, nil
}

// Fingerprint is the key's, in upper-case hex as the registries show it.
func (k Key) Fingerprint() string { return fmt.Sprintf("%X", k.entity.PrimaryKey.Fingerprint) }

// WritePublic writes the armoured public key: what a registry is given once.
func (k Key) WritePublic(w io.Writer) error {
	a, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	if err := k.entity.Serialize(a); err != nil {
		return fmt.Errorf("kmspgp: %w", err)
	}
	return a.Close()
}

// Sign writes the detached binary signature of message: GoReleaser's <artifact>.sig, as gpg
// --detach-sign writes it.
func (k Key) Sign(w io.Writer, message io.Reader, at time.Time) error {
	cfg := *k.config
	cfg.Time = func() time.Time { return at }
	if err := openpgp.DetachSign(w, k.entity, message, &cfg); err != nil {
		// go-crypto drops the signer's own error (a shadowed err in Signature.Sign) and answers that
		// nothing was signed: what KMS said is the reason worth saying.
		if s, ok := k.entity.PrivateKey.PrivateKey.(*kmsSigner); ok && s.failed != nil {
			err = s.failed
		}
		return fmt.Errorf("kmspgp: %w", err)
	}
	return nil
}

// KMS is what Sign asks of AWS KMS: its signature over a digest, and the key's public half.
type KMS interface {
	Sign(ctx context.Context, keyID string, digest []byte) ([]byte, error)
	PublicKey(ctx context.Context, keyID string) (*rsa.PublicKey, error)
}

// kmsSigner is a crypto.Signer whose private key is the KMS key keyID: RSASSA-PKCS1-v1_5 over a
// SHA-256 digest, which is what an OpenPGP RSA signature is.
type kmsSigner struct {
	ctx   context.Context //nolint:containedctx // crypto.Signer takes none, and each Sign is one call under it
	kms   KMS
	keyID string
	pub   *rsa.PublicKey
	// failed is KMS's last refusal, which go-crypto does not pass on.
	failed error
}

// NewKMSSigner is the KMS key keyID as a crypto.Signer.
func NewKMSSigner(ctx context.Context, k KMS, keyID string) (Signer, error) {
	pub, err := k.PublicKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("kmspgp: %s's public key: %w", keyID, err)
	}
	return &kmsSigner{ctx: ctx, kms: k, keyID: keyID, pub: pub}, nil
}

func (s *kmsSigner) Public() crypto.PublicKey { return s.pub }

func (s *kmsSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("kmspgp: KMS is asked for SHA-256 signatures, and this is %v", opts.HashFunc())
	}
	sig, err := s.kms.Sign(s.ctx, s.keyID, digest)
	if err != nil {
		s.failed = fmt.Errorf("KMS's signature: %w", err)
		return nil, s.failed
	}
	return sig, nil
}

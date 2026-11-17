package kmspgp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type fakeAPI struct {
	pub    []byte
	usage  kmstypes.KeyUsageType
	signed *kms.SignInput
	fail   error
}

func (f *fakeAPI) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.signed = in
	if f.fail != nil {
		return nil, f.fail
	}
	return &kms.SignOutput{Signature: []byte("signature")}, nil
}

func (f *fakeAPI) GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	return &kms.GetPublicKeyOutput{PublicKey: f.pub, KeyUsage: f.usage}, nil
}

func der(t *testing.T, pub any) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// KMS is asked to sign the digest it is handed, as RSASSA-PKCS1-v1_5 over SHA-256, and its key is
// taken only as an RSA signing key.
func TestKMSIsAskedForAnRSASignatureOverTheDigest(t *testing.T) {
	f := &fakeAPI{pub: der(t, &testKey.PublicKey), usage: kmstypes.KeyUsageTypeSignVerify}
	a := AWS{Client: f}
	pub, err := a.PublicKey(t.Context(), "alias/k")
	if err != nil || pub.N.Cmp(testKey.N) != 0 {
		t.Fatalf("public key %v, %v", pub, err)
	}
	sig, err := a.Sign(t.Context(), "alias/k", []byte("digest"))
	if err != nil || string(sig) != "signature" {
		t.Fatalf("signature %q, %v", sig, err)
	}
	if aws.ToString(f.signed.KeyId) != "alias/k" || string(f.signed.Message) != "digest" ||
		f.signed.MessageType != kmstypes.MessageTypeDigest || f.signed.SigningAlgorithm != kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256 {
		t.Fatalf("asked %+v", f.signed)
	}

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		api  *fakeAPI
		says string
	}{
		"an encryption key": {&fakeAPI{pub: der(t, &testKey.PublicKey), usage: kmstypes.KeyUsageTypeEncryptDecrypt}, "not for signing"},
		"an ECDSA key":      {&fakeAPI{pub: der(t, &ec.PublicKey), usage: kmstypes.KeyUsageTypeSignVerify}, "take RSA"},
		"not a key":         {&fakeAPI{pub: []byte("x"), usage: kmstypes.KeyUsageTypeSignVerify}, "asn1"},
		"refused":           {&fakeAPI{fail: errors.New("AccessDenied")}, "AccessDenied"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := (AWS{Client: tc.api}).PublicKey(t.Context(), "alias/k"); err == nil || !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("err = %v, want %q", err, tc.says)
			}
		})
	}
	if _, err := (AWS{Client: &fakeAPI{fail: errors.New("throttled")}}).Sign(t.Context(), "alias/k", nil); err == nil {
		t.Fatal("a refused signature was answered")
	}
}

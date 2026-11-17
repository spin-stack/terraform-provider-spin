package kmspgp

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSAPI is what AWS answers for: the two calls a release makes of the key.
type KMSAPI interface {
	Sign(ctx context.Context, in *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

var _ KMSAPI = (*kms.Client)(nil)

// AWS is KMS as the release workflow reaches it.
type AWS struct{ Client KMSAPI }

// Sign is KMS's RSASSA-PKCS1-v1_5 signature over a SHA-256 digest computed here: the digest, not
// the message, goes to KMS.
func (a AWS) Sign(ctx context.Context, keyID string, digest []byte) ([]byte, error) {
	out, err := a.Client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(keyID),
		Message:          digest,
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return nil, err
	}
	return out.Signature, nil
}

// PublicKey is the key's RSA public half.
func (a AWS) PublicKey(ctx context.Context, keyID string) (*rsa.PublicKey, error) {
	out, err := a.Client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, err
	}
	if out.KeyUsage != kmstypes.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("%s is a key for %s, not for signing", keyID, out.KeyUsage)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s is a %T key, and the registries take RSA", keyID, pub)
	}
	return rsaPub, nil
}

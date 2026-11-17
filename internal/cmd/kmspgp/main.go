// Command kmspgp signs a release's checksums with the provider's KMS key, as OpenPGP, and prints
// that key's public half for the registries:
//
//	kmspgp -key alias/terraform-provider-spin-signing public       # the armoured key, once per registry
//	kmspgp -key alias/terraform-provider-spin-signing sign -out SHA256SUMS.sig SHA256SUMS
//
// AWS credentials are the SDK's own: the release workflow's role (spin-stack/ci's signing.tf).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/spin-stack/terraform-provider-spin/internal/kmspgp"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, newKMS); err != nil {
		fmt.Fprintln(os.Stderr, "kmspgp:", err) //nolint:errcheck // the exit status says it
		os.Exit(1)
	}
}

func newKMS(ctx context.Context) (kmspgp.KMS, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("AWS credentials: %w", err)
	}
	return kmspgp.AWS{Client: kms.NewFromConfig(cfg)}, nil
}

func run(ctx context.Context, args []string, stdout io.Writer, connect func(context.Context) (kmspgp.KMS, error)) error {
	fs := flag.NewFlagSet("kmspgp", flag.ContinueOnError)
	keyID := fs.String("key", "", "the KMS key: its id, ARN or alias")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyID == "" || fs.NArg() == 0 {
		return errors.New("usage: kmspgp -key <kms key> public | sign -out <signature> <file>")
	}
	k, err := connect(ctx)
	if err != nil {
		return err
	}
	signer, err := kmspgp.NewKMSSigner(ctx, k, *keyID)
	if err != nil {
		return err
	}
	key, err := kmspgp.New(signer, kmspgp.Created)
	if err != nil {
		return err
	}
	switch fs.Arg(0) {
	case "public":
		if _, err := fmt.Fprintf(stdout, "# %s, fingerprint %s\n", kmspgp.UserID, key.Fingerprint()); err != nil {
			return err
		}
		return key.WritePublic(stdout)
	case "sign":
		return sign(key, fs.Args()[1:])
	default:
		return fmt.Errorf("%q is neither public nor sign", fs.Arg(0))
	}
}

func sign(key kmspgp.Key, args []string) (err error) {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	out := fs.String("out", "", "where the detached signature is written")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 1 {
		return errors.New("usage: kmspgp -key <kms key> sign -out <signature> <file>")
	}
	in, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }() // read only
	w, err := os.Create(*out)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, w.Close()) }()
	return key.Sign(w, in, time.Now())
}

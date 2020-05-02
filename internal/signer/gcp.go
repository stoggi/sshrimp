package signer

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// KMSSigner a GCP asymetric crypto signer
type GCPSigner struct {
	crypto.Signer
	ctx    context.Context
	client *kms.KeyManagementClient
	key    string
}

// NewGCPSSigner return a new instsance of NewGCPSSigner
func NewGCPSSigner(key string) *GCPSigner {
	ctx := context.Background()
	c, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		panic(err)
	}

	return &GCPSigner{
		ctx:    ctx,
		client: c,
		key:    key,
	}
}

// Public returns the public key from KMS
func (s *GCPSigner) Public() crypto.PublicKey {

	response, err := s.client.GetPublicKey(s.ctx, &kmspb.GetPublicKeyRequest{
		Name: s.key,
	})
	if err != nil {
		fmt.Printf(err.Error())
		return nil
	}

	pubPem := response.GetPem()
	// pubAlg := response.GetAlgorithm()
	pemBlock, _ := pem.Decode([]byte(pubPem))

	publicKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		fmt.Printf(err.Error())
		return nil
	}

	return publicKey
}

// Sign a digest with the private key in KMS
func (s *GCPSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var dig *kmspb.Digest = &kmspb.Digest{}
	switch opts {
	case crypto.SHA256:
		dig.Digest = &kmspb.Digest_Sha256{
			Sha256: digest,
		}
	case crypto.SHA384:
		dig.Digest = &kmspb.Digest_Sha384{
			Sha384: digest,
		}
	case crypto.SHA512:
		dig.Digest = &kmspb.Digest_Sha512{
			Sha512: digest,
		}
	}

	response, err := s.client.AsymmetricSign(s.ctx, &kmspb.AsymmetricSignRequest{
		Name:   s.key,
		Digest: dig,
	})
	if err != nil {
		return nil, err
	}

	return response.GetSignature(), nil
}

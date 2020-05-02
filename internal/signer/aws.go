package signer

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

// KMSSigner an AWS asymetric crypto signer
type AWSSigner struct {
	crypto.Signer
	client kmsiface.KMSAPI
	key    string
}

// NewKMSSigner return a new instsance of AWSSigner
func NewAWSSigner(key string) *AWSSigner {

	sess := session.Must(session.NewSession())

	return &AWSSigner{
		key:    key,
		client: kms.New(sess),
	}
}

// Public returns the public key from KMS
func (s *AWSSigner) Public() crypto.PublicKey {

	response, err := s.client.GetPublicKey(&kms.GetPublicKeyInput{
		KeyId: &s.key,
	})
	if err != nil {
		fmt.Printf(err.Error())
		return nil
	}

	publicKey, err := x509.ParsePKIXPublicKey(response.PublicKey)
	if err != nil {
		fmt.Printf(err.Error())
		return nil
	}

	return publicKey
}

// Sign a digest with the private key in KMS
func (s *AWSSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {

	response, err := s.client.Sign(&kms.SignInput{
		KeyId:            &s.key,
		Message:          digest,
		MessageType:      aws.String(kms.MessageTypeDigest),
		SigningAlgorithm: aws.String(kms.SigningAlgorithmSpecRsassaPkcs1V15Sha256),
	})
	if err != nil {
		return nil, err
	}

	return response.Signature, nil
}

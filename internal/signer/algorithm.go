package signer

import (
	"crypto"
	"errors"
	"io"

	"golang.org/x/crypto/ssh"
)

type sshAlgorithmSigner struct {
	algorithm string
	signer    ssh.AlgorithmSigner
}

// PublicKey returns the wrapped signers public key
func (s *sshAlgorithmSigner) PublicKey() ssh.PublicKey {
	return s.signer.PublicKey()
}

// Sign uses the correct algorithm to sign the certificate
func (s *sshAlgorithmSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.signer.SignWithAlgorithm(rand, data, s.algorithm)
}

// NewAlgorithmSignerFromSigner returns a ssh.Signer with a different default algorithm.
// Waiting for upstream changes to x/crypto/ssh, see: https://github.com/golang/go/issues/36261
func NewAlgorithmSignerFromSigner(signer crypto.Signer, algorithm string) (ssh.Signer, error) {
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, err
	}
	algorithmSigner, ok := sshSigner.(ssh.AlgorithmSigner)
	if !ok {
		return nil, errors.New("unable to cast to ssh.AlgorithmSigner")
	}
	s := sshAlgorithmSigner{
		signer:    algorithmSigner,
		algorithm: algorithm,
	}
	return &s, nil
}

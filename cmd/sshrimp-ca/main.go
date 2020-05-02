package main

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/stoggi/sshrimp/internal/config"
	"github.com/stoggi/sshrimp/internal/signer"
	"golang.org/x/crypto/ssh"
)

// HandleRequest handles a request to sign an SSH public key verified by an OpenIDConnect id_token
func HandleRequest(ctx context.Context, event signer.SSHrimpEvent) (*signer.SSHrimpResult, error) {

	// Make sure we are running in a lambda context, to get the requestid and ARN
	lambdaContext, ok := lambdacontext.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("lambdacontext not in ctx")
	}

	// Load the configuration file, if not exsits, exit.
	c := config.NewSSHrimp()
	if err := c.Read(config.GetPath()); err != nil {
		return nil, err
	}

	// Create the certificate struct with all our configured values
	certificate, err := signer.ValidateRequest(event, c, lambdaContext.AwsRequestID, lambdaContext.InvokedFunctionArn)
	if err != nil {
		return nil, err
	}

	// Setup our Certificate Authority signer backed by KMS
	kmsSigner := signer.NewAWSSigner(c.CertificateAuthority.KeyAlias)
	sshAlgorithmSigner, err := signer.NewAlgorithmSignerFromSigner(kmsSigner, ssh.SigAlgoRSASHA2256)
	if err != nil {
		return nil, err
	}

	// Sign the certificate!!
	if err := certificate.SignCert(rand.Reader, sshAlgorithmSigner); err != nil {
		return nil, err
	}

	// Extract the public key (certificate) to return to the user
	pubkey, err := ssh.ParsePublicKey(certificate.Marshal())
	if err != nil {
		return nil, err
	}

	// Success!
	return &signer.SSHrimpResult{
		Certificate:  string(ssh.MarshalAuthorizedKey(pubkey)),
		ErrorMessage: "",
		ErrorType:    "",
	}, nil
}

func main() {
	lambda.Start(HandleRequest)
}

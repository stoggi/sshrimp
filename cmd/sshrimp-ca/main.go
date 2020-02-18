package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/stoggi/sshrimp/internal/config"
	"github.com/stoggi/sshrimp/internal/identity"
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

	// Validate the user supplied public key
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(event.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("unable to parse public key: %v", err)
	}

	// Validate the user supplied identity token with the loaded configuration
	i, err := identity.NewIdentity(c)
	username, err := i.Validate(event.Token)
	if err != nil {
		return nil, err
	}

	// Validate and add force commands or source address options
	criticalOptions := make(map[string]string)
	if regexp.MustCompile(c.CertificateAuthority.ForceCommandRegex).MatchString(event.ForceCommand) {
		if event.ForceCommand != "" {
			criticalOptions["force-command"] = event.ForceCommand
		}
	} else {
		return nil, errors.New("forcecommand validation failed")
	}
	if regexp.MustCompile(c.CertificateAuthority.SourceAddressRegex).MatchString(event.SourceAddress) {
		if event.SourceAddress != "" {
			criticalOptions["source-address"] = event.SourceAddress
		}
	} else {
		return nil, errors.New("sourceaddress validation failed")
	}

	// Generate a random nonce for the certificate
	bytes := make([]byte, 32)
	nonce := make([]byte, len(bytes)*2)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	hex.Encode(nonce, bytes)

	// Generate a random serial number
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}

	// Validate and set the certificate valid and expire times
	now := time.Now()
	validAfterOffset, err := time.ParseDuration(c.CertificateAuthority.ValidAfterOffset)
	if err != nil {
		return nil, err
	}
	validBeforeOffset, err := time.ParseDuration(c.CertificateAuthority.ValidBeforeOffset)
	if err != nil {
		return nil, err
	}
	validAfter := now.Add(validAfterOffset)
	validBefore := now.Add(validBeforeOffset)

	// Convert the extensions slice to a map
	extensions := make(map[string]string, len(c.CertificateAuthority.Extensions))
	for _, extension := range c.CertificateAuthority.Extensions {
		extensions[extension] = ""
	}

	// Create a key ID to be added to the certificate. Follows BLESS Key ID format
	// https://github.com/Netflix/bless
	keyID := fmt.Sprintf("request[%s] for[%s] from[%s] command[%s] ssh_key[%s] ca[%s] valid_to[%s]",
		lambdaContext.AwsRequestID,
		username,
		event.SourceAddress,
		event.ForceCommand,
		ssh.FingerprintSHA256(publicKey),
		lambdaContext.InvokedFunctionArn,
		validBefore.Format("2006/01/02 15:04:05"),
	)

	// Create the certificate struct with all our configured alues
	certificate := ssh.Certificate{
		Nonce:    nonce,
		Key:      publicKey,
		Serial:   serial.Uint64(),
		CertType: ssh.UserCert,
		KeyId:    keyID,
		ValidPrincipals: []string{
			username,
		},
		Permissions: ssh.Permissions{
			CriticalOptions: criticalOptions,
			Extensions:      extensions,
		},
		ValidAfter:  uint64(validAfter.Unix()),
		ValidBefore: uint64(validBefore.Unix()),
	}

	// Setup our Certificate Authority signer backed by KMS
	kmsSigner := signer.NewKMSSigner(c.CertificateAuthority.KeyAlias)
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

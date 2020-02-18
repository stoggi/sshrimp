package signer

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/pkg/errors"
	"github.com/stoggi/sshrimp/internal/config"
	"golang.org/x/crypto/ssh"
)

// SSHrimpResult encodes the payload format returned from the sshrimp-ca lambda
type SSHrimpResult struct {
	Certificate  string `json:"certificate"`
	ErrorMessage string `json:"errorMessage"`
	ErrorType    string `json:"errorType"`
}

// SSHrimpEvent encodes the user input for the sshrimp-ca lambda
type SSHrimpEvent struct {
	PublicKey     string `json:"publickey"`
	Token         string `json:"token"`
	SourceAddress string `json:"sourceaddress"`
	ForceCommand  string `json:"forcecommand"`
}

// SignCertificateAllRegions iterate through each configured region if there is an error signing the certificate
func SignCertificateAllRegions(publicKey ssh.PublicKey, token string, forceCommand string, c *config.SSHrimp) (*ssh.Certificate, error) {
	var err error

	// Try each configured region before exiting if there is an error
	for _, region := range c.CertificateAuthority.Regions {
		cert, err := SignCertificateOneRegion(publicKey, token, forceCommand, region, c)
		if err == nil {
			return cert, nil
		}
	}
	return nil, err
}

// SignCertificateOneRegion given a public key, identity token and forceCommand, invoke the sshrimp-ca lambda function
func SignCertificateOneRegion(publicKey ssh.PublicKey, token string, forceCommand string, region string, c *config.SSHrimp) (*ssh.Certificate, error) {
	// Create a lambdaService using the new temporary credentials for the role
	session := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))
	lambdaService := lambda.New(session)

	// Setup the JSON payload for the SSHrimp CA
	payload, err := json.Marshal(SSHrimpEvent{
		PublicKey:    string(ssh.MarshalAuthorizedKey(publicKey)),
		Token:        token,
		ForceCommand: forceCommand,
	})
	if err != nil {
		return nil, err
	}

	// Invoke the SSHrimp lambda
	result, err := lambdaService.Invoke(&lambda.InvokeInput{
		FunctionName: aws.String(c.CertificateAuthority.FunctionName),
		Payload:      payload,
	})
	if err != nil {
		return nil, err
	}
	if *result.StatusCode != 200 {
		return nil, fmt.Errorf("sshrimp returned status code %d", *result.StatusCode)
	}

	// Parse the result form the lambda to extract the certificate
	sshrimpResult := SSHrimpResult{}
	err = json.Unmarshal(result.Payload, &sshrimpResult)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse json response from sshrimp-ca")
	}

	// These error types and messages can also come from the aws-sdk-go lambda handler
	if sshrimpResult.ErrorType != "" || sshrimpResult.ErrorMessage != "" {
		return nil, fmt.Errorf("%s: %s", sshrimpResult.ErrorType, sshrimpResult.ErrorMessage)
	}

	// Parse the certificate received by sshrimp-ca
	cert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshrimpResult.Certificate))
	if err != nil {
		return nil, err
	}
	return cert.(*ssh.Certificate), nil
}

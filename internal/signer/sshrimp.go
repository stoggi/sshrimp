package signer

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/pkg/errors"
	"github.com/stoggi/sshrimp/internal/config"
	"github.com/stoggi/sshrimp/internal/identity"

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
	var (
		err  error
		cert *ssh.Certificate
	)

	// Try each configured region before exiting if there is an error

	for _, region := range c.CertificateAuthority.Regions {
		if i := sort.SearchStrings(config.SupportedAwsRegions, region); i < len(config.SupportedAwsRegions) && config.SupportedAwsRegions[i] == region {
			cert, err = SignCertificateAWS(publicKey, token, forceCommand, region, c)
		} else if i := sort.SearchStrings(config.SupportedGcpRegions, region); i < len(config.SupportedGcpRegions) && config.SupportedGcpRegions[i] == region {
			cert, err = SignCertificateGCP(publicKey, token, forceCommand, region, c)
		}
		if err == nil {
			return cert, nil
		}
	}
	return nil, err
}

// SignCertificateGCP given a public key, identity token and forceCommand, invoke the sshrimp-ca GCP function
func SignCertificateGCP(publicKey ssh.PublicKey, token string, forceCommand string, region string, c *config.SSHrimp) (*ssh.Certificate, error) {

	// Setup the JSON payload for the SSHrimp CA
	payload, err := json.Marshal(SSHrimpEvent{
		PublicKey:    string(ssh.MarshalAuthorizedKey(publicKey)),
		Token:        token,
		ForceCommand: forceCommand,
	})
	if err != nil {
		return nil, err
	}

	result, err := http.Post(fmt.Sprintf("https://%s-%s.cloudfunctions.net/%s", region, c.CertificateAuthority.Project, c.CertificateAuthority.FunctionName), "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, errors.Wrap(err, "http post failed: "+err.Error())
	}
	if result.StatusCode != 200 {
		return nil, fmt.Errorf("sshrimp returned status code %d", result.StatusCode)
	}

	resbody, err := ioutil.ReadAll(result.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to retrieve the response from sshrimp-ca")
	}

	// Parse the result form the lambda to extract the certificate
	sshrimpResult := SSHrimpResult{}
	err = json.Unmarshal(resbody, &sshrimpResult)
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

// SignCertificateAWS given a public key, identity token and forceCommand, invoke the sshrimp-ca lambda function
func SignCertificateAWS(publicKey ssh.PublicKey, token string, forceCommand string, region string, c *config.SSHrimp) (*ssh.Certificate, error) {
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

func ValidateRequest(event SSHrimpEvent, c *config.SSHrimp, requestID string, functionID string) (ssh.Certificate, error) {
	// Validate the user supplied public key
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(event.PublicKey))
	if err != nil {
		return ssh.Certificate{}, fmt.Errorf("unable to parse public key: %v", err)
	}

	// Validate the user supplied identity token with the loaded configuration
	i, err := identity.NewIdentity(c)
	username, err := i.Validate(event.Token)
	if err != nil {
		return ssh.Certificate{}, err
	}

	// Validate and add force commands or source address options
	criticalOptions := make(map[string]string)
	if regexp.MustCompile(c.CertificateAuthority.ForceCommandRegex).MatchString(event.ForceCommand) {
		if event.ForceCommand != "" {
			criticalOptions["force-command"] = event.ForceCommand
		}
	} else {
		return ssh.Certificate{}, errors.New("forcecommand validation failed")
	}
	if regexp.MustCompile(c.CertificateAuthority.SourceAddressRegex).MatchString(event.SourceAddress) {
		if event.SourceAddress != "" {
			criticalOptions["source-address"] = event.SourceAddress
		}
	} else {
		return ssh.Certificate{}, errors.New("sourceaddress validation failed")
	}

	// Generate a random nonce for the certificate
	bytes := make([]byte, 32)
	nonce := make([]byte, len(bytes)*2)
	if _, err := rand.Read(bytes); err != nil {
		return ssh.Certificate{}, err
	}
	hex.Encode(nonce, bytes)

	// Generate a random serial number
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return ssh.Certificate{}, err
	}

	// Validate and set the certificate valid and expire times
	now := time.Now()
	validAfterOffset, err := time.ParseDuration(c.CertificateAuthority.ValidAfterOffset)
	if err != nil {
		return ssh.Certificate{}, err
	}
	validBeforeOffset, err := time.ParseDuration(c.CertificateAuthority.ValidBeforeOffset)
	if err != nil {
		return ssh.Certificate{}, err
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
		requestID,
		username,
		event.SourceAddress,
		event.ForceCommand,
		ssh.FingerprintSHA256(publicKey),
		functionID,
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
	return certificate, nil
}

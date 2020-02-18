package sshrimpagent

import (
	"crypto/rand"
	"errors"
	"time"

	"github.com/stoggi/aws-oidc/provider"
	"github.com/stoggi/sshrimp/internal/config"
	"github.com/stoggi/sshrimp/internal/signer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type sshrimpAgent struct {
	providerConfig provider.ProviderConfig
	signer         ssh.Signer
	certificate    *ssh.Certificate
	token          *provider.OAuth2Token
	config         *config.SSHrimp
}

// NewSSHrimpAgent returns an agent.Agent capable of signing certificates with a SSHrimp Certificate Authority
func NewSSHrimpAgent(c *config.SSHrimp, signer ssh.Signer) agent.Agent {

	providerConfig := provider.ProviderConfig{
		ClientID:     c.Agent.ClientID,
		ClientSecret: c.Agent.ClientSecret,
		ProviderURL:  c.Agent.ProviderURL,
		PKCE:         true,
		Nonce:        true,
		AgentCommand: c.Agent.BrowserCommand,
	}

	return &sshrimpAgent{
		providerConfig: providerConfig,
		signer:         signer,
		certificate:    &ssh.Certificate{},
		token:          &provider.OAuth2Token{},
		config:         c,
	}
}

// RemoveAll clears the current certificate and identity token (including refresh token)
func (r *sshrimpAgent) RemoveAll() error {
	r.certificate = &ssh.Certificate{}
	r.token = &provider.OAuth2Token{}
	return nil
}

// Remove has the same functionality as RemoveAll
func (r *sshrimpAgent) Remove(key ssh.PublicKey) error {
	return r.RemoveAll()
}

// Lock is not supported on this agent
func (r *sshrimpAgent) Lock(passphrase []byte) error {
	return errors.New("sshrimp-agent: locking not supported")
}

// Unlock is not supported on this agent
func (r *sshrimpAgent) Unlock(passphrase []byte) error {
	return errors.New("sshrimp-agent: unlocking not supported")
}

// List returns the identities, but also signs the certificate using sshrimp-ca if expired.
func (r *sshrimpAgent) List() ([]*agent.Key, error) {

	unixNow := time.Now().Unix()
	before := int64(r.certificate.ValidBefore)
	if r.certificate.ValidBefore != uint64(ssh.CertTimeInfinity) && (unixNow >= before || before < 0) {
		// Certificate has expired
		err := r.providerConfig.Authenticate(r.token)
		if err != nil {
			return nil, err
		}

		cert, err := signer.SignCertificateAllRegions(r.signer.PublicKey(), r.token.IDToken, "", r.config)
		if err != nil {
			return nil, err
		}
		r.certificate = cert
	}

	var ids []*agent.Key
	ids = append(ids, &agent.Key{
		Format:  r.certificate.Type(),
		Blob:    r.certificate.Marshal(),
		Comment: r.certificate.KeyId,
	})
	return ids, nil
}

// Add is not supported on this agent. For multiple OIDC backends, run multiple agents.
func (r *sshrimpAgent) Add(key agent.AddedKey) error {
	return errors.New("sshrimp-agent: adding identities not supported")
}

// Sign uses our private key to sign the challenge required to authenticate to the ssh host.
func (r *sshrimpAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return r.signer.Sign(rand.Reader, data)
}

// Signers list our current signers which there is only one.
func (r *sshrimpAgent) Signers() ([]ssh.Signer, error) {
	return []ssh.Signer{
		r.signer,
	}, nil
}

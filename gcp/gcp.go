package gcp

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/stoggi/sshrimp/internal/config"
	"github.com/stoggi/sshrimp/internal/signer"
	"golang.org/x/crypto/ssh"
)

func httpError(w http.ResponseWriter, v interface{}, statusCode int) {
	e := json.NewEncoder(w)
	err := e.Encode(v)
	http.Error(w, err.Error(), statusCode)
}

// HandleRequest handles a request to sign an SSH public key verified by an OpenIDConnect id_token
func SSHrimp(w http.ResponseWriter, r *http.Request) {

	// Load the configuration file, if not exsits, exit.
	c := config.NewSSHrimp()
	if err := c.Read(config.GetPath()); err != nil {
		httpError(w, signer.SSHrimpResult{"", err.Error(), http.StatusText(http.StatusInternalServerError)}, http.StatusInternalServerError)
		return
	}

	var event signer.SSHrimpEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		httpError(w, signer.SSHrimpResult{"", err.Error(), http.StatusText(http.StatusBadRequest)}, http.StatusBadRequest)
		return
	}

	certificate, err := signer.ValidateRequest(event, c, r.Header.Get("Function-Execution-Id"), fmt.Sprintf("%s/%s/%s", os.Getenv("GCP_PROJECT"), os.Getenv("FUNCTION_REGION"), os.Getenv("FUNCTION_NAME")))
	if err != nil {
		httpError(w, signer.SSHrimpResult{"", err.Error(), http.StatusText(http.StatusBadRequest)}, http.StatusBadRequest)
		return
	}

	// Setup our Certificate Authority signer backed by KMS
	kmsSigner := signer.NewGCPSSigner(c.CertificateAuthority.KeyAlias)

	sshAlgorithmSigner, err := signer.NewAlgorithmSignerFromSigner(kmsSigner, ssh.SigAlgoRSASHA2256)
	if err != nil {
		httpError(w, signer.SSHrimpResult{"", err.Error(), http.StatusText(http.StatusBadRequest)}, http.StatusBadRequest)
		return
	}

	// Sign the certificate!!
	if err := certificate.SignCert(rand.Reader, sshAlgorithmSigner); err != nil {
		httpError(w, signer.SSHrimpResult{"", err.Error(), http.StatusText(http.StatusBadRequest)}, http.StatusBadRequest)
		return
	}

	// Extract the public key (certificate) to return to the user
	pubkey, err := ssh.ParsePublicKey(certificate.Marshal())
	if err != nil {
		httpError(w, signer.SSHrimpResult{"", err.Error(), http.StatusText(http.StatusBadRequest)}, http.StatusBadRequest)
		return
	}

	// Success!
	res := &signer.SSHrimpResult{
		Certificate:  string(ssh.MarshalAuthorizedKey(pubkey)),
		ErrorMessage: "",
		ErrorType:    "",
	}
	e := json.NewEncoder(w)
	err = e.Encode(res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}

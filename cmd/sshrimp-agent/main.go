package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/alecthomas/kong"

	"github.com/stoggi/sshrimp/internal/config"
	"github.com/stoggi/sshrimp/internal/sshrimpagent"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var cli struct {
	Config string `kong:"arg,type='string',help='sshrimp config file (default: ${config_file} or ${env_var_name} environment variable)',default='${config_file}',env='SSHRIMP_CONFIG'"`
}

func main() {
	ctx := kong.Parse(&cli,
		kong.Name("sshrimp-agent"),
		kong.Description("An SSH Agent that renews SSH certificates automatically from a SSHrimp Certificate Authority."),
		kong.Vars{
			"config_file":  config.DefaultPath,
			"env_var_name": config.EnvVarName,
		},
	)

	c := config.NewSSHrimpWithDefaults()
	ctx.FatalIfErrorf(c.Read(cli.Config))
	ctx.FatalIfErrorf(launchAgent(c, ctx))
}

func launchAgent(c *config.SSHrimp, ctx *kong.Context) error {

	if _, err := os.Stat(c.Agent.Socket); err == nil {
		return fmt.Errorf("socket %s already exists", c.Agent.Socket)
	}

	// This affects all files created for the process. Since this is a sensitive
	// socket, only allow the current user to write to the socket.
	syscall.Umask(0077)
	listener, err := net.Listen("unix", c.Agent.Socket)
	if err != nil {
		return err
	}
	defer listener.Close()

	ctx.Printf("listening on %s", c.Agent.Socket)

	// Generate a new SSH private/public key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return err
	}

	// Create the sshrimp agent with our configuration and the private key signer
	sshrimpAgent := sshrimpagent.NewSSHrimpAgent(c, signer)

	// Listen for signals so that we can close the listener and exit nicely
	osSignals := make(chan os.Signal)
	signal.Notify(osSignals, os.Interrupt, os.Kill)
	go func() {
		_ = <-osSignals
		listener.Close()
	}()

	// Accept connections and serve the agent
	for {
		conn, err := listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				// Occurs if the user interrupts the agent with a ctrl-c signal
				return nil
			}
			return err
		}
		if err := agent.ServeAgent(sshrimpAgent, conn); err != nil {
			return err
		}
	}
}

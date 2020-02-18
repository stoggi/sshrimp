package agent

import (
	"github.com/magefile/mage/sh"
)

// Build Builds the local ssh agent
func Build() error {
	return sh.Run("go", "build", "./cmd/sshrimp-agent")
}

// Clean Cleans the output files for sshrimp-agent
func Clean() error {
	return sh.Rm("sshrimp-agent")
}

// Install Installs the sshrimp-agent
func Install() error {
	return sh.Run("go", "install", "./cmd/sshrimp-agent")
}

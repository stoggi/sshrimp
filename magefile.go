//+build mage

package main

import (
	"fmt"
	"os"

	"github.com/magefile/mage/mg"

	// mage:import ca
	"github.com/stoggi/sshrimp/tools/mage/ca"
	// mage:import agent
	"github.com/stoggi/sshrimp/tools/mage/agent"
)

var Default = All

// Builds all the targets
func Build() {
	mg.Deps(ca.Build, agent.Build)
}

// Remove all build output (except generated configuration files)
func Clean() {
	mg.Deps(ca.Clean, agent.Clean)
}

// Build and deploy the ca and agent
func All() {
	mg.Deps(agent.Build, ca.Package, ca.Generate)

	if _, err := os.Stat("./terraform"); os.IsNotExist(err) {
		fmt.Println("All done. Run `terraform init` then `terraform apply` to deploy.")
	} else {
		fmt.Println("All done. Run `terraform apply` to deploy.")
	}
}

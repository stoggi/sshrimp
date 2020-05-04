// +build darwin linux
package main

import (
	"syscall"
)

func init() {
	sigs = append(sigs, syscall.SIGTERM, syscall.SIGHUP)
}

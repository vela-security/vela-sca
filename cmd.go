package sca

import "os/exec"

type command struct {
	exe  string
	hash string
	cmd  *exec.Cmd
}

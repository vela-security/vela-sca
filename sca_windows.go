package sca

import "syscall"

func newSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		HideWindow: true,
	}
}

package sca

import (
	"github.com/vela-security/vela-public/lua"
	"reflect"
	"time"
)

var (
	typeof = reflect.TypeOf((*sca)(nil)).String()
)

type sca struct {
	lua.ProcEx
	cfg *config
}

func newSCA(cfg *config) *sca {
	s := &sca{cfg: cfg}
	s.V(lua.PTMode, time.Now())
	return s
}

//func (s *sca) checksum() bool {
//	return auxlib.Checksum(s.cfg.exe, s.cfg.hash)
//}

func (s *sca) Name() string {
	return s.cfg.name
}

func (s *sca) Type() string {
	return typeof
}

func (s *sca) Start() error {
	return nil
}

func (s *sca) Close() error {
	return nil
}

package sca

import (
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/lua"
)

type config struct {
	name string
	exe  string
	hash string
	oss  auxlib.URL
	db   string
	co   *lua.LState
}

func (cfg *config) NewIndex(L *lua.LState, key string, val lua.LValue) {
	switch key {
	case "name":
		cfg.name = val.String()
	case "exe":
		cfg.exe = val.String()
	case "oss":
		cfg.oss = auxlib.CheckURL(val, L)
	case "hash":
		cfg.hash = val.String()
	case "db":
		cfg.db = val.String()
	}
}

func (cfg *config) valid() error {
	if e := auxlib.Name(cfg.name); e != nil {
		return e
	}

	return auxlib.Checksum(cfg.exe, cfg.hash)
}

func newConfig(L *lua.LState) *config {
	cfg := &config{
		co: xEnv.Clone(L),
	}

	tab := L.CheckTable(1)
	tab.Range(func(key string, val lua.LValue) { cfg.NewIndex(L, key, val) })

	if e := cfg.valid(); e != nil {
		L.RaiseError("%v", e)
		return cfg
	}

	return cfg
}

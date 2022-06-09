package sca

import (
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
)

var xEnv assert.Environment

func newLuaSca(L *lua.LState) int {
	cfg := newConfig(L)
	proc := L.NewProc(cfg.name, typeof)

	if proc.IsNil() {
		proc.Set(newSCA(cfg))
	} else {
		old := proc.Data.(*sca)
		old.cfg = cfg
	}

	L.Push(proc)
	return 1
}

/*
	local sca = vela.sca{
		name = "123",
		oss  = "https://ossindex.sonatype.org/api/v3/component-report?token=xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
		cpe  = "abb.db"
	}

	sca.cyclonedx("fastjson.jar").pipe(function(cmt)

	end)
*/
func WithEnv(env assert.Environment) {
	xEnv = env
	env.Set("sca", lua.NewFunction(newLuaSca))
}

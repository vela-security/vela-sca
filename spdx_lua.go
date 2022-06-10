package sca

import (
	"github.com/vela-security/vela-audit"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
)

func (s *spdx) String() string                         { return lua.B2S(s.data) }
func (s *spdx) Type() lua.LValueType                   { return lua.LTObject }
func (s *spdx) AssertFloat64() (float64, bool)         { return 0, false }
func (s *spdx) AssertString() (string, bool)           { return "", false }
func (s *spdx) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (s *spdx) Peek() lua.LValue                       { return s }

func (s *spdx) pipeL(L *lua.LState) int {
	n := len(s.value.Packages)
	if n == 0 {
		return 0
	}

	mode := L.CheckString(1)

	pip := pipe.NewByLua(L, pipe.Env(xEnv), pipe.Seek(1))
	if pip.Len() == 0 {
		return 0
	}

	filter := func(ex sdxEx) bool {
		return true
	}

	switch mode {
	case "purl":
		filter = func(ex sdxEx) bool {
			return ex.Type == "purl"
		}
	default:

	}

	co := xEnv.Clone(L)
	defer xEnv.Free(co)

	hm := lua.NewMap(4, true)
	for i := 0; i < n; i++ {
		p := s.value.Packages[i]
		for _, ext := range p.External {
			if !filter(ext) {
				continue
			}
			hm.Set("file", lua.S2L(s.file))
			hm.Set("category", lua.S2L(ext.Category))
			hm.Set("locator", lua.S2L(ext.Locator))
			hm.Set("type", lua.S2L(ext.Type))
			pip.Do(hm, co, func(err error) {
				audit.Errorf("spdx pipe call fail %v", err).From(co.CodeVM()).Put()
			})
		}
	}

	return 0
}

func (s *spdx) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "raw":
		return lua.B2L(s.data)
	case "pipe":
		return lua.NewFunction(s.pipeL)

	}

	return lua.LNil
}

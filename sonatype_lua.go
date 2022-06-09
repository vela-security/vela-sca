package sca

import (
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
)

func (s sonatype) rangeL(L *lua.LState) int {
	fn := L.IsFunc(1)
	if fn == nil {
		return 0
	}

	n := len(s.Vulnerabilities)
	if n == 0 {
		return 0
	}
	co := xEnv.Clone(L)
	defer xEnv.Free(co)

	hm := lua.NewMap(10, true)
	for i := 0; i < n; i++ {
		v := s.Vulnerabilities[i]
		hm.Set("purl", lua.S2L(s.Coordinates))
		hm.Set("p_desc", lua.S2L(s.Description))
		hm.Set("p_refer", lua.S2L(s.Reference))
		hm.Set("id", lua.S2L(v.ID))
		hm.Set("cve", lua.S2L(v.Cve))
		hm.Set("score", lua.LNumber(v.CvssScore))
		hm.Set("vector", lua.S2L(v.CvssVector))
		hm.Set("desc", lua.S2L(v.Description))
		hm.Set("name", lua.S2L(v.DisplayName))
		hm.Set("cwe", lua.S2L(v.Cwe))
		hm.Set("title", lua.S2L(v.Title))
		hm.Set("reference", lua.S2L(v.Reference))
		xEnv.Call(co, fn, hm)
	}

	return 0
}

func (s sonatype) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "range":
		return lua.NewFunction(s.rangeL)
	case "coordinates":
		return lua.S2L(s.Coordinates)
	case "desc":
		return lua.S2L(s.Description)
	case "refer":
		return lua.S2L(s.Reference)
	}
	return nil
}

func (ss sonatypes) String() string                         { return "sca.sonatypes" }
func (ss sonatypes) Type() lua.LValueType                   { return lua.LTObject }
func (ss sonatypes) AssertFloat64() (float64, bool)         { return 0, false }
func (ss sonatypes) AssertString() (string, bool)           { return "", false }
func (ss sonatypes) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (ss sonatypes) Peek() lua.LValue                       { return ss }

func (ss sonatypes) pipeL(L *lua.LState) int {
	n := len(ss)
	if n == 0 {
		return 0
	}
	mode := L.CheckString(1)
	pip := pipe.NewByLua(L, pipe.Env(xEnv), pipe.Seek(1))
	if pip.Len() == 0 {
		return 0
	}

	filter := func(s sonatype) bool {
		return true
	}

	switch mode {
	case "vul":
		filter = func(s sonatype) bool {
			return len(s.Vulnerabilities) > 0
		}
	default:

	}
	co := xEnv.Clone(L)
	defer xEnv.Free(co)

	for i := 0; i < n; i++ {
		s := ss[i]

		if !filter(s) {
			continue
		}

		pip.Do(lua.NewAnyData(s, lua.Reflect(lua.ELEM)), co, func(err error) {
			xEnv.Errorf("sonatype pipe call fail %v", err)
		})
	}

	return 0
}

func (ss sonatypes) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "pipe":
		return lua.NewFunction(ss.pipeL)

	}
	return lua.LNil
}

package sca

import (
	audit "github.com/vela-security/vela-audit"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
)

func (cmt component) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "purl":
		return lua.S2L(cmt.PackageURL)
	case "cpe":
		return lua.S2L(cmt.CPE)
	case "mime":
		return lua.S2L(cmt.MIMEType)
	case "group":
		return lua.S2L(cmt.Group)
	case "copyright":
		return lua.S2L(cmt.Copyright)
	}
	return nil
}

func (c *cyclonedx) String() string                         { return lua.B2S(c.data) }
func (c *cyclonedx) Type() lua.LValueType                   { return lua.LTObject }
func (c *cyclonedx) AssertFloat64() (float64, bool)         { return 0, false }
func (c *cyclonedx) AssertString() (string, bool)           { return "", false }
func (c *cyclonedx) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (c *cyclonedx) Peek() lua.LValue                       { return c }

func (c *cyclonedx) pipeL(L *lua.LState) int {
	n := len(c.cxt.Components)
	if n == 0 {
		return 0
	}

	pip := pipe.NewByLua(L, pipe.Env(xEnv))
	if pip.Len() == 0 {
		return 0
	}

	co := xEnv.Clone(L)
	defer xEnv.Free(co)

	for i := 0; i < n; i++ {
		cmt := c.cxt.Components[i]
		pip.Do(lua.NewAnyData(cmt, lua.Reflect(lua.ELEM)), co, func(err error) {
			audit.Errorf("spdx pipe call fail %v", err).From(co.CodeVM()).Put()
		})
	}

	return 0
}

func (c *cyclonedx) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "raw":
		return lua.B2L(c.data)
	case "pipe":
		return lua.NewFunction(c.pipeL)

	}

	return lua.LNil
}

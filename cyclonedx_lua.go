package sca

import (
	audit "github.com/vela-security/vela-audit"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
)

func (c *cyclonedx) String() string                         { return "sca.cyclonedx" }
func (c *cyclonedx) Type() lua.LValueType                   { return lua.LTObject }
func (c *cyclonedx) AssertFloat64() (float64, bool)         { return 0, false }
func (c *cyclonedx) AssertString() (string, bool)           { return "", false }
func (c *cyclonedx) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (c *cyclonedx) Peek() lua.LValue                       { return c }

func (c *cyclonedx) pipeL(L *lua.LState) int {
	n := len(c.sbom.Components)
	if n == 0 {
		return 0
	}

	pip := pipe.NewByLua(L, pipe.Env(xEnv))
	if pip.Len() == 0 {
		return 0
	}

	co := xEnv.Clone(L)
	for i := 0; i < n; i++ {
		cmt := c.sbom.Components[i]
		pip.Do(lua.NewAnyData(cmt, lua.Reflect(lua.ELEM)), co, func(err error) {
			audit.Errorf("cyclonedx pipe call fail %v", err).From(co.CodeVM()).Put()
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

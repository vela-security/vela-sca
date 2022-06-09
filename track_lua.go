package sca

import "github.com/vela-security/vela-public/lua"

func (t *track) String() string                         { return "sca.track" }
func (t *track) Type() lua.LValueType                   { return lua.LTObject }
func (t *track) AssertFloat64() (float64, bool)         { return 0, false }
func (t *track) AssertString() (string, bool)           { return "", false }
func (t *track) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (t *track) Peek() lua.LValue                       { return t }

func (t *track) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "ok":
		return lua.LBool(t.err == nil)

	case "err":
		if t.err == nil {
			return lua.LNil
		}
		return lua.S2L(t.err.Error())

	case "cdx":
		return t.cdx

	case "son":
		return sonatypes(t.son)

	}

	return lua.LNil
}

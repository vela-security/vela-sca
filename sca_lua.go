package sca

import "github.com/vela-security/vela-public/lua"

func (s *sca) cyclonedxL(L *lua.LState) int {
	filename := L.CheckString(1)
	c := newCyclonedx(s.cfg.exe, filename)
	c.Invoke()
	L.Push(c)
	return 1
}

func (s *sca) trackL(L *lua.LState) int {
	filename := L.CheckString(1)
	L.Push(s.track(filename))
	return 1
}

func (s *sca) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "cyclonedx":
		return lua.NewFunction(s.cyclonedxL)
	case "track":
		return lua.NewFunction(s.trackL)

	}
	return lua.LNil
}

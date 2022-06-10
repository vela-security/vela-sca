package sca

import "github.com/vela-security/vela-public/lua"

func (s *sca) cyclonedxL(L *lua.LState) int {
	filename := L.CheckString(1)
	c := newCyclonedx(s.cfg.exe, filename)
	c.Invoke()
	L.Push(c)
	return 1
}

func (s *sca) spdxL(L *lua.LState) int {
	filename := L.CheckString(1)
	sx := newSpdx(s.cfg.exe, filename)
	sx.Invoke()
	L.Push(sx)
	return 1
}

func (s *sca) trackL(L *lua.LState) int {
	filename := L.CheckString(1)
	flag := L.IsTrue(2)
	L.Push(s.track(filename, flag))
	return 1
}

func (s *sca) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "cyclonedx":
		return lua.NewFunction(s.cyclonedxL)
	case "spdx":
		return lua.NewFunction(s.spdxL)
	case "track":
		return lua.NewFunction(s.trackL)

	}
	return lua.LNil
}

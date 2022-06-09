package sca

import (
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/vela-security/vela-public/lua"
)

type component cdx.Component

type sbom struct {
	BomFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"SpecVersion"`
	SerialNumber string       `json:"serialNumber"`
	Metadata     cdx.Metadata `json:"metadata"`
	Components   []component  `json:"components"`
}

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

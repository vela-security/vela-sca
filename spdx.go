package sca

import (
	"encoding/json"
	audit "github.com/vela-security/vela-audit"
	"github.com/vela-security/vela-public/catch"
	"github.com/vela-security/vela-public/kind"
	"os"
	"os/exec"
	"strings"
)

type sdxEx struct {
	Category string `json:"referenceCategory"`
	Locator  string `json:"referenceLocator"`
	Type     string `json:"referenceType"`
}

type sdxPackage struct {
	ID string `json:"SPDXID"`

	Checksums []struct {
		Algorithm     string `json:"algorithm"`
		ChecksumValue string `json:"checksumValue"`
	} `json:"checksums"`

	Location         string  `json:"downloadLocation"`
	External         []sdxEx `json:"externalRefs"`
	FilesAnalyzed    bool    `json:"filesAnalyzed"`
	LicenseConcluded string  `json:"licenseConcluded"`
	LicenseDeclared  string  `json:"licenseDeclared"`
	Name             string  `json:"name"`
	Source           string  `json:"sourceInfo"`
	Version          string  `json:"versionInfo"`
}

type sdx struct {
	ID       string `json:"SPDXID"`
	Creation struct {
		Created            string   `json:"created"`
		Creators           []string `json:"creators"`
		LicenseListVersion string   `json:"licenseListVersion"`
	} `json:"creationInfo"`
	DataLicense       string       `json:"dataLicense"`
	DocumentNamespace string       `json:"documentNamespace"`
	Name              string       `json:"name"`
	SpdxVersion       string       `json:"spdxVersion"`
	Packages          []sdxPackage `json:"packages"`
}

type spdx struct {
	exe   string
	file  string
	data  []byte
	value sdx
	info  os.FileInfo
	cause *catch.Cause
}

func newSpdx(exe string, filename string) *spdx {
	c := &spdx{
		exe:   exe,
		file:  filename,
		cause: catch.New(),
	}

	info, err := os.Stat(filename)
	if err != nil {
		c.cause.Try(c.file, err)
	} else {
		c.info = info
	}
	return c
}

func (s *spdx) Invoke() {
	cmd := exec.Command(s.exe, s.file, "--output=spdx-json")
	defer func() {
		if cmd.Process == nil {
			return
		}
		cmd.Process.Kill()
		audit.Debug("%s spdx parse succeed", s.file)
	}()

	cmd.SysProcAttr = newSysProcAttr()
	raw, err := cmd.Output()
	if err != nil {
		s.cause.Try("fork exec "+s.exe, err)
		return
	}
	s.data = raw

	err = json.Unmarshal(raw, &s.value)
	if err != nil {
		audit.Debug("%s spdx decode fail %v", s.file, err)
	}
}

func (s *spdx) PackageURL() []byte {
	n := len(s.value.Packages)
	if n == 0 {
		return nil
	}

	var data []string
	for i := 0; i < n; i++ {
		p := s.value.Packages[i]
		for _, ext := range p.External {
			if ext.Type != "purl" {
				continue
			}

			if iv := strings.IndexByte(ext.Category, '@'); iv < 0 {
				data[i] = ext.Category + "@0.0.0"
				continue
			}

			data = append(data, ext.Category)
		}
	}

	enc := kind.NewJsonEncoder()
	enc.Tab("")
	enc.Join("coordinates", data)
	enc.End("}")
	return enc.Bytes()
}

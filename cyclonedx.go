package sca

import (
	"encoding/json"
	"github.com/vela-security/vela-audit"
	"github.com/vela-security/vela-public/catch"
	"github.com/vela-security/vela-public/kind"
	"os"
	"os/exec"
)

type cyclonedx struct {
	exe   string
	file  string
	data  []byte
	sbom  sbom
	info  os.FileInfo
	cause *catch.Cause
}

func newCyclonedx(exe string, filename string) *cyclonedx {
	c := &cyclonedx{
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

func (c *cyclonedx) Invoke() {
	cmd := exec.Command(c.exe, c.file, "--output=cyclonedx-json")
	defer func() {
		if cmd.Process == nil {
			return
		}
		cmd.Process.Kill()
		audit.Debug("%s cyclonedx parse succeed", c.file)
	}()

	cmd.SysProcAttr = newSysProcAttr()
	raw, err := cmd.Output()
	if err != nil {
		c.cause.Try("fork exec "+c.exe, err)
		return
	}
	c.data = raw

	err = json.Unmarshal(raw, &c.sbom)
	if err != nil {
		audit.Debug("%s cyclonedx decode fail %v", c.file, err)
	}
}

func (c *cyclonedx) PackageURL() []byte {
	n := len(c.sbom.Components)
	if n == 0 {
		return nil
	}

	data := make([]string, n)
	for i := 0; i < n; i++ {
		data[i] = c.sbom.Components[i].PackageURL
	}

	enc := kind.NewJsonEncoder()
	enc.Tab("")
	enc.Join("coordinates", data)
	enc.End("}")
	return enc.Bytes()
}

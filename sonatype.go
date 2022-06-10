package sca

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type vul struct {
	Cve                string   `json:"cve"`
	CvssScore          float32  `json:"cvssScore"`
	CvssVector         string   `json:"cvssVector"`
	Cwe                string   `json:"cwe"`
	Description        string   `json:"description"`
	DisplayName        string   `json:"displayName"`
	ExternalReferences []string `json:"externalReferences"`
	ID                 string   `json:"id"`
	Reference          string   `json:"reference"`
	Title              string   `json:"title"`
}

type sonatype struct {
	Coordinates     string `json:"coordinates"`
	Description     string `json:"description"`
	Reference       string `json:"reference"`
	Vulnerabilities []vul  `json:"vulnerabilities"`
}

type sonatypes []sonatype

func (s *sca) SonatypeHttp(body []byte) (*http.Response, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("empty body")
	}

	if s.cfg.oss.IsNil() {
		return nil, fmt.Errorf("not found sonatype ossindex")
	}

	r, err := http.NewRequest("POST", s.cfg.oss.Request(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	r.Header.Add("Accept", "application/vnd.ossindex.component-report.v1+json")
	r.Header.Add("Content-Type", "application/vnd.ossindex.component-report-request.v1+json")
	r.Header.Add("Authorization", "Basic "+s.cfg.oss.Value("token"))
	r.Header.Add("User-Agent", "vela-security-http-client-v1.0")

	client := http.Client{}
	return client.Do(r)
}

func (s *sca) Sonatype(v *[]sonatype, body []byte) error {
	r, err := s.SonatypeHttp(body)
	if err != nil {
		return err
	}

	if r.StatusCode != http.StatusOK {
		return err
	}

	return json.NewDecoder(r.Body).Decode(v)
}

func (s *sca) SonaTypeByEnv(v *[]sonatype, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty body")
	}

	return xEnv.PostJSON("/v1/vulnerability/sonatype", json.RawMessage(data), v)

	//path := "/proxy/sonatype/api/v3/authorized/component-report"
	//method := "POST"
	//body := bytes.NewReader(data)
	//query := fmt.Sprintf("time=%d", time.Now().Unix())
	//header := http.Header{}
	//header.Add("Accept", "application/vnd.ossindex.component-report.v1+json")
	//header.Add("Content-Type", "application/vnd.ossindex.component-report-request.v1+json")
	//header.Add("User-Agent", "vela-security-http-client-v1.0")

	//return xEnv.HTTP(method, path, query, body, header).JSON(v)
}

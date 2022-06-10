package sca

type track struct {
	cdx *cyclonedx
	son []sonatype
	err error
}

func (s *sca) track(filename string, flag bool) *track { //flag: true  use tunnel client
	cdx := newCyclonedx(s.cfg.exe, filename)
	cdx.Invoke()

	if cdx.cause.Len() != 0 {
		return &track{cdx: cdx, err: cdx.cause.Wrap()}
	}

	var v []sonatype
	var err error
	if flag {
		err = s.SonaTypeByEnv(&v, cdx.PackageURL())
	} else {
		err = s.Sonatype(&v, cdx.PackageURL())
	}

	return &track{cdx: cdx, son: v, err: err}
}

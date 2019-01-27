package certificate

import (
	"os"
	"path"

	"github.com/albertogviana/easyrsa"
)

// Certificate has the configuration need to run easyrsa
type Certificate struct {
	*Config
}

// Config has all the dependencies that certificate needs to run
type Config struct {
	easyRSA *easyrsa.EasyRSA
}

// NewCertificate returns a new instance of Certificate
func NewCertificate(easyrsa *easyrsa.EasyRSA) (*Certificate, error) {
	certificate := &Certificate{
		&Config{
			easyRSA: easyrsa,
		},
	}

	err := certificate.initialize()
	if err != nil {
		return nil, err
	}

	return certificate, nil
}

func (c *Certificate) initialize() error {
	err := c.easyRSA.InitPKI()
	if err != nil {
		return err
	}

	_, caCertificateErr := os.Stat(path.Join(c.easyRSA.PKIDir, "ca.crt"))
	if caCertificateErr == nil {
		return nil
	}

	err = c.easyRSA.BuildCA()
	if err != nil {
		return err
	}

	return nil
}

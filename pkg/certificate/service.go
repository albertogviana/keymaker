package certificate

import "github.com/albertogviana/easyrsa"

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

	err := certificate.bootstrap()
	if err != nil {
		return nil, err
	}

	return certificate, nil
}

func (c *Certificate) bootstrap() error {
	err := c.easyRSA.InitPKI()
	if err != nil {
		return err
	}

	err = c.easyRSA.BuildCA()
	if err != nil {
		return err
	}

	return nil
}

package certificate

import (
	"fmt"
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

	_, dhErr := os.Stat(path.Join(c.easyRSA.PKIDir, "dh.pem"))
	if dhErr == nil {
		return nil
	}

	err = c.easyRSA.GenDH()
	if err != nil {
		return err
	}

	return nil
}

// GenerateServerCertificate creates the server certificate and key
func (c *Certificate) GenerateServerCertificate(requestName string) error {
	_, errPrivate := os.Stat(path.Join(c.easyRSA.PKIDir, "private", fmt.Sprintf("%s.key", requestName)))
	_, errReqs := os.Stat(path.Join(c.easyRSA.PKIDir, "reqs", fmt.Sprintf("%s.req", requestName)))

	if errPrivate == nil && errReqs == nil {
		return fmt.Errorf("%s server certificate already exists", requestName)
	}

	err := c.requestAndSign("server", requestName)
	if err != nil {
		return err
	}

	return nil
}

func (c *Certificate) requestAndSign(typeSign, requestName string) error {
	err := c.easyRSA.GenReq(requestName)
	if err != nil {
		return err
	}

	err = c.easyRSA.SignReq(typeSign, requestName)
	if err != nil {
		return err
	}

	return nil
}

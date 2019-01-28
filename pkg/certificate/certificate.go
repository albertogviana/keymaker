package certificate

import (
	"errors"
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

const ServerTypeSign = "server"
const ClientTypeSign = "client"

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

// GenerateCertificate creates server or client certificate and key
func (c *Certificate) GenerateCertificate(typeSign, requestName string) error {
	if typeSign != ServerTypeSign && typeSign != ClientTypeSign {
		return errors.New("invalid type, please use server or client")
	}

	_, errPrivate := os.Stat(path.Join(c.easyRSA.PKIDir, "private", fmt.Sprintf("%s.key", requestName)))
	_, errReqs := os.Stat(path.Join(c.easyRSA.PKIDir, "reqs", fmt.Sprintf("%s.req", requestName)))
	_, errCrt := os.Stat(path.Join(c.easyRSA.PKIDir, "issued", fmt.Sprintf("%s.crt", requestName)))

	if errPrivate == nil && errReqs == nil && errCrt == nil {
		return fmt.Errorf("%s %s certificate already exists", requestName, typeSign)
	}

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

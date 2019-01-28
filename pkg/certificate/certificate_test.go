package certificate

import (
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/albertogviana/easyrsa"
	"github.com/stretchr/testify/suite"
)

type ServiceTestSuite struct {
	suite.Suite
	EasyRSA *easyrsa.EasyRSA
	PKIDir  string
}

func TestServiceTestSuite(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}

func (c *ServiceTestSuite) SetupTest() {
	dir := fmt.Sprintf("/tmp/easy-rsa-pki-%d", time.Now().UnixNano())
	os.Mkdir(dir, 0755)

	config := easyrsa.Config{
		BinDir:           "/tmp/easy-rsa",
		PKIDir:           dir,
		CommonName:       "my-test-cn",
		CountryCode:      "BR",
		Province:         "Sao Paulo",
		City:             "Sao Paulo",
		Organization:     "Unit Test",
		Email:            "admin@example.com",
		OrganizationUnit: "Test",
	}

	easyRSA, err := easyrsa.NewEasyRSA(config)
	c.NoError(err)

	c.EasyRSA = easyRSA
	c.PKIDir = dir
}

func (c *ServiceTestSuite) TearDownTest() {
	os.RemoveAll(c.PKIDir)
}

func (c *ServiceTestSuite) Test_NewCertificate() {
	expectedCertificate := &Certificate{
		&Config{
			c.EasyRSA,
		},
	}

	certificate, err := NewCertificate(c.EasyRSA)
	c.NoError(err)
	c.Equal(expectedCertificate, certificate)
	_, err = os.Stat(path.Join(c.EasyRSA.PKIDir, "ca.crt"))
	c.NoError(err)
	_, err = os.Stat(path.Join(c.EasyRSA.PKIDir, "dh.pem"))
	c.NoError(err)
}

func (c *ServiceTestSuite) Test_NewCertificateCAAlreadyCreated() {
	err := c.EasyRSA.InitPKI()
	c.NoError(err)

	err = c.EasyRSA.BuildCA()
	c.NoError(err)

	_, err = NewCertificate(c.EasyRSA)
	c.NoError(err)
}

func (c *ServiceTestSuite) Test_GenerateServerCertificate() {
	certificate, err := NewCertificate(c.EasyRSA)
	c.NoError(err)

	err = certificate.GenerateServerCertificate("server")
	c.NoError(err)

	_, err = os.Stat(path.Join(c.EasyRSA.PKIDir, "private", "server.key"))
	c.NoError(err)

	_, err = os.Stat(path.Join(c.EasyRSA.PKIDir, "reqs", "server.req"))
	c.NoError(err)

	_, err = os.Stat(path.Join(c.EasyRSA.PKIDir, "issued", "server.crt"))
	c.NoError(err)
}

func (c *ServiceTestSuite) Test_GenerateServerCertificate_AlreadyExists() {
	certificate, err := NewCertificate(c.EasyRSA)
	c.NoError(err)

	err = certificate.GenerateServerCertificate("server")
	c.NoError(err)

	err = certificate.GenerateServerCertificate("server")
	c.EqualError(err, "server server certificate already exists")
}

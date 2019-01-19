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

func (c *ServiceTestSuite) TearDownSuite() {
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
}

func (c *ServiceTestSuite) Test_NewCertificateCAAlreadyCreated() {
	err := c.EasyRSA.InitPKI()
	c.NoError(err)

	err = c.EasyRSA.BuildCA()
	c.NoError(err)

	errString := `Generating RSA private key, 2048 bit long modulus
	...................+++
	...............................................................+++
	e is 65537 (0x010001)

	Easy-RSA error:

	Unable to create a CA as you already seem to have one set up.
	If you intended to start a new CA, run init-pki first.`

	_, err = NewCertificate(c.EasyRSA)
	c.EqualError(err, errString)
}

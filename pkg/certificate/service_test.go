package certificate

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type ServiceTestSuite struct {
	suite.Suite
}

func TestServiceTestSuite(t *testing.T) {
	suite.Run(t, new(ServiceTestSuite))
}

func (e *ServiceTestSuite) Test_NewEasyRSA() {
	expectedEasyRSA := &EasyRSA{Config{
		BinDir:     "/tmp/easy-rsa",
		PKIDir:     "/tmp/easy-rsa",
		CommonName: "my-test-cn",
		KeySize:    2048,
		CAExpire:   3650,
	}}

	config := Config{
		BinDir:     "/tmp/easy-rsa",
		PKIDir:     "/tmp/easy-rsa",
		CommonName: "my-test-cn",
	}

	easyRSA, err := NewEasyRSA(config)
	e.NoError(err)
	e.Equal(expectedEasyRSA, easyRSA)
}

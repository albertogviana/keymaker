package easyrsa

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"regexp"
)

// EasyRSA struct
type EasyRSA struct {
	Config
}

// Config has all the configuration needed to run easyrsa
type Config struct {
	BinDir           string // Easy-RSA top-level dir, where the easyrsa script is located.
	PKIDir           string // Used to hold all PKI-specific files
	CommonName       string // Common name used to generate the certificates
	KeySize          int    // Set the keysize in bits to generate
	CAExpire         int    // In how many days should the root CA key expire?
	ServerName       string // Server name
	CountryCode      string
	Province         string
	City             string
	Organization     string
	Email            string
	OrganizationUnit string
}

const errCAAlreadyExist = "Easy-RSA error:\n\nUnable to create a CA as you already seem to have one set up.\nIf you intended to start a new CA, run init-pki first.\n"

// NewEasyRSA returns an instance of EasyRSA
func NewEasyRSA(config Config) (*EasyRSA, error) {
	err := validate(config)
	if err != nil {
		return nil, err
	}

	if config.KeySize == 0 {
		config.KeySize = 2048
	}

	if config.CAExpire == 0 {
		config.CAExpire = 3650
	}

	easyRSA := &EasyRSA{
		config,
	}

	return easyRSA, nil
}

// InitPKI initializes a directory for the PKI.
func (e *EasyRSA) InitPKI() error {
	_, privateErr := os.Stat(path.Join(e.PKIDir, "private"))
	_, reqsErr := os.Stat(path.Join(e.PKIDir, "reqs"))

	if privateErr == nil && reqsErr == nil {
		return nil
	}

	return e.run("init-pki")
}

// BuildCA generates the Certificate Authority (CA)
func (e *EasyRSA) BuildCA() error {
	err := e.run("build-ca", "nopass")

	if err == nil {
		return nil
	}

	re := regexp.MustCompile("Easy-RSA error:(?s)(.*)")
	regexResult := re.FindString(string(err.Error()))

	if regexResult == errCAAlreadyExist {
		return errors.New(errCAAlreadyExist)
	}

	return err
}

// GenReq generates a keypair and request
func (e *EasyRSA) GenReq(requestName string) error {
	return e.run("gen-req", requestName, "nopass")
}

// SignReq signs a request, and you can have the following types:
// 	- client - A TLS client, suitable for a VPN user or web browser (web client)
// 	- server - A TLS server, suitable for a VPN or web server
func (e *EasyRSA) SignReq(typeSign, requestName string) error {
	if typeSign != "server" && typeSign != "client" {
		return errors.New("invalid type, please use server or client")
	}

	return e.run("sign-req", typeSign, requestName)
}

// ImportReq import requests from external systems that are requesting
// a signed certificate from this CA
func (e *EasyRSA) ImportReq(requestFile, requestName string) error {
	if _, err := os.Stat(requestFile); os.IsNotExist(err) {
		return err
	}
	return e.run("import-req", requestFile, requestName)
}

// GenDH creates a strong Diffie-Hellman key to use during key exchange
func (e *EasyRSA) GenDH() error {
	return e.run("gen-dh")
}

// Revoke revokes a certificate, after you revoke the certificate it is a
// good practive to update the CRL file, and send it to the VPN Server
// https://github.com/OpenVPN/easy-rsa/blob/v3.0.6/doc/EasyRSA-Readme.md#revoking-and-publishing-crls
func (e *EasyRSA) Revoke(requestName string) error {
	return e.run("revoke", requestName)
}

// GenCRL generates a CRL suitable for publishing to systems that rely, otherwise
// the revoke certificate will be available
func (e *EasyRSA) GenCRL() error {
	return e.run("gen-crl")
}

func (e *EasyRSA) getEnvironmentVariable() []string {
	var vars []string

	vars = append(vars, fmt.Sprintf("EASYRSA=%s", e.BinDir))
	vars = append(vars, fmt.Sprintf("EASYRSA_PKI=%s", e.PKIDir))
	vars = append(vars, fmt.Sprintf("EASYRSA_REQ_CN=%s", e.CommonName))
	vars = append(vars, fmt.Sprintf("EASYRSA_CA_EXPIRE=%d", e.CAExpire))
	vars = append(vars, fmt.Sprintf("EASYRSA_KEY_SIZE=%d", e.KeySize))
	vars = append(vars, fmt.Sprintf("EASYRSA_REQ_COUNTRY=%s", e.CountryCode))
	vars = append(vars, fmt.Sprintf("EASYRSA_REQ_PROVINCE=%s", e.Province))
	vars = append(vars, fmt.Sprintf("EASYRSA_REQ_CITY=%s", e.City))
	vars = append(vars, fmt.Sprintf("EASYRSA_REQ_ORG=%s", e.Organization))
	vars = append(vars, fmt.Sprintf("EASYRSA_REQ_EMAIL=%s", e.Email))
	vars = append(vars, fmt.Sprintf("EASYRSA_REQ_OU=%s", e.OrganizationUnit))
	vars = append(vars, "EASYRSA_BATCH=1")

	return vars
}

func (e *EasyRSA) run(args ...string) error {
	environment := e.getEnvironmentVariable()

	var stderrBuf bytes.Buffer

	cmd := exec.Command(path.Join(e.BinDir, "easyrsa"), args...)
	cmd.Env = append(os.Environ(), environment...)

	stderrIn, _ := cmd.StderrPipe()
	stderr := io.MultiWriter(os.Stderr, &stderrBuf)

	cmd.Stdout = os.Stdout

	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("cmd.Start() failed with '%s'", err)
	}

	go func() {
		io.Copy(stderr, stderrIn)
	}()

	err = cmd.Wait()

	if err == nil {
		return nil
	}

	return errors.New(string(stderrBuf.Bytes()))
}

func validate(config Config) error {
	if config.BinDir == "" {
		return errors.New("the path to easy-rsa directory was not define")
	}

	if config.PKIDir == "" {
		return errors.New("the path to the pki directory was not define")
	}

	if config.CommonName == "" {
		return errors.New("the common name was not define")
	}

	if _, err := os.Stat(config.BinDir); os.IsNotExist(err) {
		return err
	}

	if _, err := os.Stat(path.Join(config.BinDir, "easyrsa")); os.IsNotExist(err) {
		return err
	}

	return nil
}

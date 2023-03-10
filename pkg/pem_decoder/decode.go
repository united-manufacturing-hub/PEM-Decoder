package pem_decoder

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func ParseCertificate(pemCert []byte) (*x509.Certificate, error) {
	// Decode the PEM encoded certificate
	block, _ := pem.Decode(pemCert)
	var blockBytes []byte
	if block == nil {
		blockBytes = pemCert
	} else {
		blockBytes = block.Bytes
	}

	// Parse the certificate from the DER-encoded bytes
	cert, err := x509.ParseCertificate(blockBytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func ParseRSAPrivateKey(pemPrivateKey []byte) (key *rsa.PrivateKey, err error) {
	// Decode the PEM encoded private key
	block, _ := pem.Decode(pemPrivateKey)
	var blockBytes []byte
	if block == nil {
		blockBytes = pemPrivateKey
	} else {
		blockBytes = block.Bytes
	}

	// Parse the DER-encoded bytes of the private key
	key, err = x509.ParsePKCS1PrivateKey(blockBytes)
	if err != nil {
		// Try parsing as PKCS8
		var keyX any
		keyX, err = x509.ParsePKCS8PrivateKey(blockBytes)
		if err != nil {
			return nil, err
		}
		switch keyX.(type) {
		case *rsa.PrivateKey:
			key = keyX.(*rsa.PrivateKey)
		default:
			return nil, errors.New("unsupported private key type")
		}
	}

	return key, nil
}

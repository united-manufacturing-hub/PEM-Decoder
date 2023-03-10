package pem_decoder

import (
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path"
	"testing"
)

const testFilePathCerts = "testfiles/certificates"
const testFilePathPKeys = "testfiles/privateKeys"

func TestParseCertificate(t *testing.T) {
	files, err := os.ReadDir(testFilePathCerts)
	if err != nil {
		t.Fatal(err)
	}
	var bytes []byte
	for _, file := range files {
		bytes, err = os.ReadFile(path.Join(testFilePathCerts, file.Name()))
		if err != nil {
			t.Logf("Error reading file %s", file.Name())
			t.Fatal(err)
		}
		var c *x509.Certificate
		c, err = ParseCertificate(bytes)
		if err != nil {
			t.Logf("Error parsing file %s", file.Name())
			t.Fatal(err)
		}
		t.Logf("Parsed certificate %v (issued by %v)", c.Subject, c.Issuer)
	}
}

func TestParseRSAPrivateKey(t *testing.T) {
	files, err := os.ReadDir(testFilePathPKeys)
	if err != nil {
		t.Fatal(err)
	}
	var bytes []byte
	for _, file := range files {
		bytes, err = os.ReadFile(path.Join(testFilePathPKeys, file.Name()))
		if err != nil {
			t.Logf("Error reading file %s", file.Name())
			t.Fatal(err)
		}

		var c *rsa.PrivateKey
		c, err = ParseRSAPrivateKey(bytes)
		if err != nil {
			t.Logf("Error parsing file %s", file.Name())
			t.Fatal(err)
		}
		t.Logf("Parsed private key %v", c)
	}
}

package ocsp

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/crypto/ocsp"
)

// ocspHTTP matches http.DefaultClient: no overall timeout, default redirects,
// and a transport with DefaultTransport's dial timeout, keep-alive, and TLS
// (nil TLSClientConfig, HTTP/2 still attempted). It is not DefaultClient.
// Dialer Control runs ApplyDialerControllers. A protect error fails that
// dial. It is not retried on http.DefaultTransport.
var ocspHTTP = &http.Client{Transport: newProtectedHTTPTransport()}

func newProtectedHTTPTransport() *http.Transport {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return internet.ApplyDialerControllers(network, address, c)
		},
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func GetOCSPForFile(path string) ([]byte, error) {
	return filesystem.ReadFile(path)
}

func CheckOCSPFileIsNotExist(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		return os.IsNotExist(err)
	}
	return false
}

func GetOCSPStapling(cert [][]byte, path string) ([]byte, error) {
	ocspData, err := GetOCSPForFile(path)
	if err != nil {
		ocspData, err = GetOCSPForCert(cert)
		if err != nil {
			return nil, err
		}
		if !CheckOCSPFileIsNotExist(path) {
			err = os.Remove(path)
			if err != nil {
				return nil, err
			}
		}
		newFile, err := os.Create(path)
		if err != nil {
			return nil, err
		}
		newFile.Write(ocspData)
		defer newFile.Close()
	}
	return ocspData, nil
}

func GetOCSPForCert(cert [][]byte) ([]byte, error) {
	bundle := new(bytes.Buffer)
	for _, derBytes := range cert {
		err := pem.Encode(bundle, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		if err != nil {
			return nil, err
		}
	}
	pemBundle := bundle.Bytes()

	certificates, err := parsePEMBundle(pemBundle)
	if err != nil {
		return nil, err
	}
	issuedCert := certificates[0]
	if len(issuedCert.OCSPServer) == 0 {
		return nil, errors.New("no OCSP server specified in cert")
	}
	if len(certificates) == 1 {
		if len(issuedCert.IssuingCertificateURL) == 0 {
			return nil, errors.New("no issuing certificate URL")
		}
		resp, errC := ocspHTTP.Get(issuedCert.IssuingCertificateURL[0])
		if errC != nil {
			return nil, errors.New("no issuing certificate URL").Base(errC)
		}
		defer resp.Body.Close()

		issuerBytes, errC := io.ReadAll(resp.Body)
		if errC != nil {
			return nil, errors.New(errC)
		}

		issuerCert, errC := x509.ParseCertificate(issuerBytes)
		if errC != nil {
			return nil, errors.New(errC)
		}

		certificates = append(certificates, issuerCert)
	}
	issuerCert := certificates[1]

	ocspReq, err := ocsp.CreateRequest(issuedCert, issuerCert, nil)
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(ocspReq)
	req, err := ocspHTTP.Post(issuedCert.OCSPServer[0], "application/ocsp-request", reader)
	if err != nil {
		return nil, errors.New(err)
	}
	defer req.Body.Close()
	ocspResBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, errors.New(err)
	}
	return ocspResBytes, nil
}

// parsePEMBundle parses a certificate bundle from top to bottom and returns
// a slice of x509 certificates. This function will error if no certificates are found.
func parsePEMBundle(bundle []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	var certDERBlock *pem.Block

	for {
		certDERBlock, bundle = pem.Decode(bundle)
		if certDERBlock == nil {
			break
		}

		if certDERBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(certDERBlock.Bytes)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, cert)
		}
	}

	if len(certificates) == 0 {
		return nil, errors.New("no certificates were found while parsing the bundle")
	}

	return certificates, nil
}

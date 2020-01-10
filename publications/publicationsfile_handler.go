/*
 * Copyright 2020 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

package publications

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fullsailor/pkcs7"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/log"
)

// FileHandler is publications file (see File) processor.
type FileHandler struct {
	// Download URI.
	uri string

	// Publications file.
	file         *File
	fileTTL      time.Duration
	fileCachedAt time.Time
	fileCnstr    []pkix.AttributeTypeAndValue

	// Cert trust store.
	trustedCertificates *x509.CertPool

	// Receive guard.
	rxMutex sync.Mutex
}

const (
	defaultPubFileTTL = time.Hour * 8
)

// NewFileHandler returns a new publications file handler instance.
func NewFileHandler(settings ...FileHandlerSetting) (*FileHandler, error) {
	tmp := fileHandler{obj: FileHandler{
		fileTTL: defaultPubFileTTL,
	}}
	// Setup adjust settings with provided.
	for _, setter := range settings {
		if setter == nil {
			return nil, errors.New(errors.KsiInvalidArgumentError).AppendMessage("Setting is a nil pointer.")
		}
		if err := setter(&tmp); err != nil {
			return nil, err
		}
	}

	return &tmp.obj, nil
}

// FileHandlerSetting is handler initialization option.
type (
	FileHandlerSetting func(*fileHandler) error
	fileHandler        struct {
		obj FileHandler
	}
)

// FileHandlerUseSystemCertStore initializes the trust store with a copy of the system cert pool.
func FileHandlerUseSystemCertStore() FileHandlerSetting {
	return func(h *fileHandler) error {
		if h == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing file handler base object.")
		}

		pool, err := x509.SystemCertPool()
		if err != nil {
			return errors.New(errors.KsiCryptoFailure).SetExtError(err).
				AppendMessage("Unable to set system cert pool.")
		}
		h.obj.trustedCertificates = pool

		return nil
	}
}

// FileHandlerSetTrustedCertificateDir is configuration method that takes a directory path as input,
// locates all files with 'crt' extension and loads them as trusted certificates.
func FileHandlerSetTrustedCertificateDir(path string) FileHandlerSetting {
	return func(h *fileHandler) error {
		if h == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing file handler base object.")
		}

		// Open directory for inspection.
		files, err := ioutil.ReadDir(path)
		if err != nil {
			return errors.New(errors.KsiIoError).SetExtError(err).
				AppendMessage(fmt.Sprintf("Unable to load certificate directory '%s'.", path))
		}

		hasCerts := false
		// Loop over directory content.
		for _, f := range files {
			name := f.Name()
			if f.IsDir() || !strings.HasSuffix(name, ".crt") {
				continue
			}

			hasCerts = true
			var (
				certPath   = filepath.Join(path, name)
				certSetter = FileHandlerSetTrustedCertificateFromFilePem(certPath)
			)
			if err := certSetter(h); err != nil {
				return errors.KsiErr(err).
					AppendMessage(fmt.Sprintf("Unable to add certificate '%s' to trusted certificates.", certPath))
			}
		}

		if !hasCerts {
			log.Info(fmt.Sprintf("No certificates added from directory '%s'.", path))
		}

		return nil
	}
}

// FileHandlerSetTrustedCertificate is configuration method that appends certificate to pool of trusted
// certificates.
func FileHandlerSetTrustedCertificate(certificate *x509.Certificate) FileHandlerSetting {
	return func(h *fileHandler) error {
		if h == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing file handler base object.")
		}
		if certificate == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}

		if h.obj.trustedCertificates == nil {
			h.obj.trustedCertificates = x509.NewCertPool()
			if h.obj.trustedCertificates == nil {
				return errors.New(errors.KsiCryptoFailure).AppendMessage("Unable to initialize cert pool.")
			}
		}
		h.obj.trustedCertificates.AddCert(certificate)

		return nil
	}
}

// FileHandlerSetTrustedCertificateFromFilePem is configuration method that appends certificate(s) from pem
// encoded file to pool of trusted certificates.
func FileHandlerSetTrustedCertificateFromFilePem(fname string) FileHandlerSetting {
	return func(h *fileHandler) error {
		if h == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing file handler base object.")
		}

		dat, err := ioutil.ReadFile(fname)
		if err != nil {
			return errors.New(errors.KsiIoError).SetExtError(err).
				AppendMessage(fmt.Sprintf("Unable to open file '%s'!", fname))
		}

		if h.obj.trustedCertificates == nil {
			h.obj.trustedCertificates = x509.NewCertPool()
			if h.obj.trustedCertificates == nil {
				return errors.New(errors.KsiCryptoFailure).AppendMessage("Unable to initialize cert pool.")
			}
		}
		if !h.obj.trustedCertificates.AppendCertsFromPEM(dat) {
			return errors.New(errors.KsiInvalidFormatError).
				AppendMessage(fmt.Sprintf("Unable to append certificates from file '%s'!", fname))
		}

		return nil
	}
}

// FileHandlerSetPublicationsURL is configuration method for the publications file URL.
func FileHandlerSetPublicationsURL(url string) FileHandlerSetting {
	return func(h *fileHandler) error {
		if h == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing file handler base object.")
		}
		h.obj.uri = url
		return nil
	}
}

// OID is certificate DN object identifier.
type OID asn1.ObjectIdentifier

var (
	// OidEmail is the ASN.1 notation for Email Address attribute for use in signatures.
	OidEmail = OID([]int{1, 2, 840, 113549, 1, 9, 1})
	// OidCommonName is the ASN.1 notation for common name attribute type.
	OidCommonName = OID([]int{2, 5, 4, 3})
	// OidCountry is the ASN.1 notation for Country Name attribute type specifying a country.
	OidCountry = OID([]int{2, 5, 4, 6})
	// OidOrganization is the ASN.1 notation for Organization Name attribute type specifying an organization.
	OidOrganization = OID([]int{2, 5, 4, 10})
)

// FileHandlerSetFileCertConstraint specifies the default constraints for verifying the
// publications file PKI certificate.
//
// Can be called multiple times in order to apply different X.509 distinguished names.
func FileHandlerSetFileCertConstraint(oid OID, value string) FileHandlerSetting {
	return func(h *fileHandler) error {
		if oid == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if h == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing file handler base object.")
		}

		h.obj.fileCnstr = append(h.obj.fileCnstr, pkix.AttributeTypeAndValue{
			Type:  asn1.ObjectIdentifier(oid),
			Value: value,
		})

		return nil
	}
}

// FileHandlerSetFileCertConstraints see description of FileHandlerSetFileCertConstraint.
func FileHandlerSetFileCertConstraints(cnstrs []pkix.AttributeTypeAndValue) FileHandlerSetting {
	return func(h *fileHandler) error {
		if len(cnstrs) == 0 {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if h == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing file handler base object.")
		}
		h.obj.fileCnstr = append(h.obj.fileCnstr, cnstrs...)
		return nil
	}
}

// FileHandlerSetFile publications file setter.
// Note that if the publications URL is set, then calling ReceiveFile() will always trigger a new file download.
func FileHandlerSetFile(p *File) FileHandlerSetting {
	return func(h *fileHandler) error {
		if h == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing file handler base object.")
		}
		if p == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}

		h.obj.file = p
		// Clear the cached at time. This will always trigger a new download via ReceiveFile().
		h.obj.fileCachedAt = time.Time{}
		return nil
	}
}

// FileHandlerSetFileTTL specifies the downloaded publications file cache timeout.
//
// After the timeout expires, a call to the ReceiveFile() will trigger a new publications file download.
// In order to disable the timeout, set the duration to 0.
func FileHandlerSetFileTTL(d time.Duration) FileHandlerSetting {
	return func(h *fileHandler) error {
		if h == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing file handler base object.")
		}
		if d.Nanoseconds() < 0 {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Duration can not be negative.")
		}

		h.obj.fileTTL = d
		return nil
	}
}

// ReceiveFile downloads the publications file from the URI specified by the FileHandlerSetPublicationsURL.
//
// The downloaded publications file is cached. Sequential calls to this method will return the cached file, except
// when the cache timeout specified by FileHandlerSetFileTTL has expired, in which case a new download is triggered.
func (h *FileHandler) ReceiveFile() (*File, error) {
	if h == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}
	if h.uri == "" && h.file == nil {
		return nil, errors.New(errors.KsiInvalidStateError).AppendMessage("Publications file URL not configured.")
	}
	h.rxMutex.Lock()
	defer h.rxMutex.Unlock()

	if h.uri == "" {
		return h.file, nil
	}

	now := time.Now()
	if h.file == nil || now.Sub(h.fileCachedAt) >= h.fileTTL {
		pubFile, err := NewFile(FileFromURL(h.uri))
		if err != nil {
			return nil, err
		}
		h.file = pubFile
		h.fileCachedAt = now
	}
	return h.file, nil
}

// FileTTL returns downloaded publications file cache timeout.
func (h *FileHandler) FileTTL() (time.Duration, error) {
	if h == nil {
		return time.Duration(0), errors.New(errors.KsiInvalidArgumentError)
	}
	return h.fileTTL, nil
}

// Verify verifies the PKI signature of the publications file.
func (h *FileHandler) Verify(p *File) error {
	if h == nil || p == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}
	if p.rawTlv == nil {
		return errors.New(errors.KsiInvalidFormatError).AppendMessage("Missing raw data.")
	}
	if p.signature == nil || len(*p.signature) == 0 {
		return errors.New(errors.KsiPublicationsFileNotSignedWithPki)
	}

	// Parse the PKCS7 signature, and set signed value for verification.
	pkcs7Sig, err := pkcs7.Parse(*p.signature)
	if err != nil {
		return errors.New(errors.KsiInvalidPkiSignature).SetExtError(err).
			AppendMessage("Unable to parse publications file PKCS7 signature.")
	}

	if pkcs7Sig == nil {
		return errors.New(errors.KsiInvalidPkiSignature).AppendMessage("Unexpected error - PKCS7 signature is nil!")
	}

	pkcs7Sig.Content = p.getSignedSlice()

	if err = pkcs7Sig.Verify(); err != nil {
		return errors.New(errors.KsiInvalidPkiSignature).SetExtError(err).
			AppendMessage("Unable to verify publications file signature.")
	}

	verifyOp := &x509.VerifyOptions{
		DNSName:       "",
		Intermediates: x509.NewCertPool(),
		Roots:         h.trustedCertificates,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageAny,
		},
	}

	// Append certificates embedded into signature.
	for _, interCert := range pkcs7Sig.Certificates {
		verifyOp.Intermediates.AddCert(interCert)
	}

	signCertCount := len(pkcs7Sig.Signers)
	if signCertCount == 0 {
		return errors.New(errors.KsiInvalidPkiSignature).
			AppendMessage("There is no signer info embedded into PKCS7 signature.")
	}

	// Note that nil is returned if there is more than 1 signer.
	signerCertificate := pkcs7Sig.GetOnlySigner()
	if signerCertificate == nil {
		return errors.New(errors.KsiInvalidPkiSignature).
			AppendMessage(fmt.Sprintf("There are %v signer certificate for PKCS7 signature but only 1 is expected.", signCertCount))
	}

	// Verify certificate change.
	chain, err := signerCertificate.Verify(*verifyOp)
	if err != nil {
		return errors.New(errors.KsiInvalidPkiSignature).SetExtError(err).
			AppendMessage("Unable to verify PKCS7 signatures signing certificate.")
	}

	if err = checkCertConstraints(h.fileCnstr, signerCertificate.Subject.Names); err != nil {
		return err
	}

	// TODO: Allow multiple chains?
	if len(chain) != 1 {
		for _, cert := range chain[0] {
			if isCertExpired(cert) || !isCertValid(cert) {
				return errors.New(errors.KsiInvalidPkiSignature).
					AppendMessage("Unable to verify PKCS7 signatures signing certificate.").
					AppendMessage(fmt.Sprintf("Certificate in the chains is not valid.\n%v", CertChainToString(chain[0])))
			}
		}
	} else if len(chain) > 1 {
		return errors.New(errors.KsiInvalidPkiSignature).
			AppendMessage("Unable to verify PKCS7 signatures signing certificate.").
			AppendMessage("There is more than one certificate verification chains.")
	} else if len(chain) == 0 {
		return errors.New(errors.KsiInvalidPkiSignature).
			AppendMessage("Unexpected failure while verifying PKCS7 signatures signing certificate.").
			AppendMessage("Empty chain is returned without error.")
	}

	return nil
}

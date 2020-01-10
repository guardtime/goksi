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
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"math"
	"os"
	"strings"
	"time"

	"github.com/guardtime/goksi/errors"
	"github.com/guardtime/goksi/log"
	"github.com/guardtime/goksi/net"
	"github.com/guardtime/goksi/pdu"
	"github.com/guardtime/goksi/templates"
	"github.com/guardtime/goksi/tlv"
)

const (
	pubFileHeaderID = "KSIPUBLF"
)

func init() {
	if err := templates.Register(&File{}, "", 0x700); err != nil {
		panic(errors.KsiErr(err).AppendMessage("Failed to initialize publications 'File' template."))
	}
}

// File is a trust anchor for verifying KSI signatures. It contains a list of public-key certificates
// for verifying authentication records and a list of publications for verifying publication records
// attached to calendar hash chains. A publication file has the following components that must appear
// in the following order:
//  - 8-byte magic 4B 53 49 50 55 42 4C 46 (in hexadecimal), which encodes the string 'KSIPUBLF' in ASCII.
//  - Header (Single)
//  - Public Key Certificates (Multiple) that are considered trustworthy at the time of creation of the publication file.
//  - Publications (Multiple) that have been created up to the file creation time. Every 'publication' structure consists
//    of 'published data' and 'publication reference' structures, where the 'published data' structure consists of the
//    'publication time' and 'published hash' fields .
//  - Signature (Single) of the file.
type File struct {
	// KSI elements.
	pubHeader *pdu.PublicationsHeader   `tlv:"701,nstd,C1,IF"`
	certRecs  *[]*pdu.CertificateRecord `tlv:"702,nstd,C0_N"`
	pubRecs   *[]*pdu.PublicationRec    `tlv:"703,nstd,C0_N"`
	signature *[]byte                   `tlv:"704,bin,C1,IL"`
	// Raw TLV data for internal usage.
	rawTlv *tlv.Tlv `tlv:"basetlv"`
}

// NewFile returns publications file constructed from the provided initializer.
//
// Note that the returned publications file is not verified (see (FileHandler).Verify()).
func NewFile(builder FileBuilder) (*File, error) {
	if builder == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	var tmp file
	if err := builder(&tmp); err != nil {
		return nil, err
	}
	return &tmp.obj, nil
}

// FileBuilder defines a publications file initializer.
type (
	FileBuilder func(*file) error
	file        struct {
		obj File
	}
)

// FileFromFile returns initializer for the publications file to be built from a binary file.
func FileFromFile(path string) FileBuilder {
	return func(p *file) error {
		if p == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing publications file base object.")
		}

		f, err := os.Open(path)
		if err != nil {
			return errors.New(errors.KsiIoError).SetExtError(err).
				AppendMessage("Unable to open publications file.")

		}
		defer func() {
			if err := f.Close(); err != nil {
				log.Error("Failed to close file: ", err)
			}
		}()

		info, err := f.Stat()
		if err != nil {
			return errors.New(errors.KsiIoError).SetExtError(err).
				AppendMessage("Unable get file stats.")
		}
		if info.Size() > math.MaxUint32 {
			return errors.New(errors.KsiInvalidFormatError).
				AppendMessage("Publications file exceeds max size.")
		}

		raw, err := ioutil.ReadAll(f)
		if err != nil {
			return errors.New(errors.KsiIoError).SetExtError(err).
				AppendMessage("Unable to read publications file.")
		}

		if err := p.obj.encode(raw); err != nil {
			return err
		}
		return nil
	}
}

// FileFromBytes returns initializer for the publications file to be built from binary array.
func FileFromBytes(raw []byte) FileBuilder {
	return func(p *file) error {
		if len(raw) == 0 {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if p == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing publications file base object.")
		}

		if len(raw) > math.MaxUint32 {
			return errors.New(errors.KsiInvalidFormatError).
				AppendMessage("Publications file exceeds max size.")
		}

		return p.obj.encode(raw)
	}
}

// FileFromReader returns initializer for the publications file to be built from binary stream.
func FileFromReader(r io.Reader) FileBuilder {
	return func(p *file) error {
		if r == nil {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if p == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing publications file base object.")
		}

		lr := io.LimitReader(r, math.MaxUint32+1)
		raw, err := ioutil.ReadAll(lr)
		if err != nil {
			return errors.New(errors.KsiIoError).SetExtError(err).
				AppendMessage("Unable to read publications file stream.")
		}

		return FileFromBytes(raw)(p)
	}
}

// FileFromURL returns initializer for the publications file to be download from the specified location.
func FileFromURL(url string) FileBuilder {
	return func(p *file) error {
		if len(url) == 0 {
			return errors.New(errors.KsiInvalidArgumentError)
		}
		if p == nil {
			return errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing publications file base object.")
		}

		netClient, err := net.NewClient(url, "", "")
		if err != nil {
			return err
		}

		raw, err := netClient.Receive(nil, nil)
		if err != nil {
			return errors.KsiErr(err, errors.KsiNetworkError).AppendMessage("Network client returned error.")
		}
		if len(raw) > math.MaxUint32 {
			return errors.New(errors.KsiInvalidFormatError).
				AppendMessage("Publications file exceeds max size.")
		}

		return p.obj.encode(raw)
	}
}

func (p *File) encode(raw []byte) error {
	if p == nil || len(raw) == 0 {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	headerLen := len(pubFileHeaderID)
	if len(raw) < headerLen {
		return errors.New(errors.KsiInvalidFormatError).AppendMessage("Not enough bytes for publications file header.")
	}
	if len(raw) == headerLen {
		return errors.New(errors.KsiInvalidFormatError).AppendMessage("Only publications file header is provided.")
	}

	// Check the header.
	rawHeader := string(raw[:headerLen])
	if rawHeader != pubFileHeaderID {
		return errors.New(errors.KsiInvalidFormatError).
			AppendMessage(fmt.Sprintf("Unrecognized header: %x", raw[:headerLen]))
	}

	pduTlv, err := tlv.NewTlv(tlv.ConstructEmpty(0x700, false, false))
	if err != nil {
		return err
	}
	if err := pduTlv.SetValue(raw[headerLen:]); err != nil {
		return err
	}

	pduTemplate, err := templates.Get("File")
	if err != nil {
		return err
	}
	if err := pduTlv.ParseNested(pduTemplate); err != nil {
		return err
	}
	if err := pduTlv.ToObject(p, pduTemplate, nil); err != nil {
		return err
	}
	p.rawTlv = pduTlv
	return nil
}

func formatHexStringWithDelimiters(input string) string {
	var buf strings.Builder
	// buf := make([]byte, 0, 2*len(input))
	n := 0
	for i, char := range input {
		if i != 0 && i%2 == 0 {
			buf.WriteRune(':')
			n++
		}

		buf.WriteRune(char)
		n++
	}
	return buf.String()
}

func isCertExpired(cert *x509.Certificate) bool {
	return time.Now().After(cert.NotAfter)
}

func isCertValid(cert *x509.Certificate) bool {
	return time.Now().After(cert.NotBefore)
}

// CertificateToString returns a printable representation of the x509 certificate.
func CertificateToString(cert *x509.Certificate) string {
	if cert == nil {
		return "nil"
	}

	var stateString string

	issuerName := cert.Issuer.String()
	subjectName := cert.Subject.String()
	dateAfter := cert.NotAfter.String()
	dateBefore := cert.NotBefore.String()
	serial := cert.SerialNumber.Text(16)
	ID := fmt.Sprintf("%4x", crc32.ChecksumIEEE(cert.Raw))

	switch {
	case isCertExpired(cert):
		stateString = "expired"
	case isCertValid(cert):
		stateString = "valid"
	default:
		stateString = "invalid"
	}

	return fmt.Sprintf("PKI Certificate (%s):\n"+
		"  * Issued to: %s\n"+
		"  * Issued by: %s\n"+
		"  * Valid from: %s to %s [%s]\n"+
		"  * Serial Number: %s\n",
		formatHexStringWithDelimiters(ID), subjectName, issuerName, dateBefore, dateAfter, stateString, formatHexStringWithDelimiters(serial))
}

// CertChainToString returns a printable representation of the x509 certificate chain.
func CertChainToString(certList []*x509.Certificate) string {
	if len(certList) == 0 {
		return "nil"
	}
	var buf strings.Builder
	buf.WriteString("Certificate chain:\n\n")
	for i, cert := range certList {
		buf.WriteString(fmt.Sprintf("Certificate(%v)\n%s\n\n", i, CertificateToString(cert)))
	}

	return buf.String()
}

func checkCertConstraints(ref, subject []pkix.AttributeTypeAndValue) error {
	if len(ref) == 0 {
		return errors.New(errors.KsiPkiCertificateNotTrusted).
			AppendMessage("Unable to verify certificates constraints as constraints are not specified!")
	}

	for _, r := range ref {
		isOidMatch := false
		for _, s := range subject {
			if r.Type.Equal(s.Type) {
				isOidMatch = true

				rString, ok := r.Value.(string)
				if !ok {
					return errors.New(errors.KsiInvalidFormatError).
						AppendMessage("Unexpected error while extracting reference value from publications files constraints.").
						AppendMessage(fmt.Sprintf(" Expecting a string, but got '%v'!", r.Value))
				}

				sString, ok := s.Value.(string)
				if !ok {
					return errors.New(errors.KsiInvalidFormatError).
						AppendMessage("Unexpected error while extracting publications files constraints from certificate.").
						AppendMessage(fmt.Sprintf(" Expecting string, but got '%v'!", s.Value))
				}

				if rString != sString {
					return errors.New(errors.KsiPkiCertificateNotTrusted).
						AppendMessage(fmt.Sprintf("Certificate constraints mismatch for %s.", r.Type.String())).
						AppendMessage(fmt.Sprintf("Expecting '%s', but got '%s'!", rString, sString))
				}

				break
			}
		}

		if !isOidMatch {
			return errors.New(errors.KsiPkiCertificateNotTrusted).
				AppendMessage("Unable to verify certificate constraints").
				AppendMessage(fmt.Sprintf("Constraint '%s' is not specified in certificate!", r.Type.String()))
		}
	}

	return nil
}

func (p *File) getSignedSlice() []byte {
	if p == nil {
		return nil
	}
	rawTlvValue := p.rawTlv.Value()
	// Construct a slice containing part of publications file that was signed.
	header := []byte(pubFileHeaderID)
	rawTlvLen := len(rawTlvValue)
	sigLen := len(*p.signature) + 4
	signedTLV := rawTlvValue[0 : rawTlvLen-sigLen]

	signedData := make([]byte, 0, 8+rawTlvLen-sigLen)
	signedData = append(signedData, header...)
	signedData = append(signedData, signedTLV...)

	return signedData
}

// Certificate returns PKI certificate record with the given ID.
//
// Returns the found certificate, or nil otherwise.
func (p *File) Certificate(id []byte) (*pdu.CertificateRecord, error) {
	if p == nil || id == nil || len(id) == 0 {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	if p.certRecs != nil {
		for _, r := range *p.certRecs {
			certID, err := r.CertID()
			if err != nil {
				return nil, errors.KsiErr(err).
					AppendMessage("Inconsistent certificate record.").
					AppendMessage("Missing certificate id.")
			}
			if bytes.Equal(id, certID) {
				return r, nil
			}
		}
	}
	return nil, nil
}

// PublicationRec returns publication record based on the provided search strategy.
//
// Returns the found publication record, or nil otherwise.
func (p *File) PublicationRec(by PubRecSearchBy) (*pdu.PublicationRec, error) {
	if p == nil || by == nil {
		return nil, errors.New(errors.KsiInvalidArgumentError)
	}

	id, err := by(p)
	if err != nil {
		return nil, err
	}
	if id < 0 {
		return nil, nil
	}
	return (*p.pubRecs)[id], nil
}

// PubRecSearchBy specifies the publication record search criteria.
type PubRecSearchBy func(*File) (int, error)

// PubRecSearchByPubString searches publication by publication string.
func PubRecSearchByPubString(pubString string) PubRecSearchBy {
	return func(p *File) (int, error) {
		if len(pubString) == 0 {
			return -1, errors.New(errors.KsiInvalidArgumentError)
		}
		if p == nil {
			return -1, errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing publications file base object.")
		}

		pubData, err := pdu.NewPublicationData(pdu.PubDataFromString(pubString))
		if err != nil {
			return -1, err
		}

		if p.pubRecs == nil {
			return -1, nil
		}
		for i, r := range *p.pubRecs {
			recData, err := r.PublicationData()
			if err != nil {
				return -1, errors.KsiErr(err).AppendMessage("Failed to extract publication data.")
			}

			if pubData.Equal(recData) {
				return i, nil
			}
		}
		// No suitable publication found in the file.
		return -1, nil
	}
}

// PubRecSearchByPubData searches publication by publication record.
func PubRecSearchByPubData(pubData *pdu.PublicationData) PubRecSearchBy {
	return func(p *File) (int, error) {
		if pubData == nil {
			return -1, errors.New(errors.KsiInvalidArgumentError)
		}
		if p == nil {
			return -1, errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing publications file base object.")
		}

		if p.pubRecs == nil {
			return -1, nil
		}
		for i, r := range *p.pubRecs {
			recData, err := r.PublicationData()
			if err != nil {
				return -1, errors.KsiErr(err).AppendMessage("Failed to extract publication data.")
			}
			if pubData.Equal(recData) {
				return i, nil
			}
		}
		// No suitable publication found in the file.
		return -1, nil
	}
}

// PubRecSearchByTime searches publication by exact time.
func PubRecSearchByTime(pubTime time.Time) PubRecSearchBy {
	return func(p *File) (int, error) {
		if p == nil {
			return -1, errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing publications file base object.")
		}

		if p.pubRecs == nil {
			return -1, nil
		}
		for i, r := range *p.pubRecs {
			recPubData, err := r.PublicationData()
			if err != nil {
				return -1, errors.KsiErr(err).AppendMessage("Failed to extract publication data.")
			}

			recPubTime, err := recPubData.PublicationTime()
			if err != nil {
				return -1, errors.KsiErr(err).AppendMessage("Failed to extract publication time.")
			}
			if pubTime.Equal(recPubTime) {
				return i, nil
			}
		}
		// No suitable publication found in the file.
		return -1, nil
	}
}

// PubRecSearchLatest searches for the latest available publication, it must be published after given time.
func PubRecSearchLatest(pubTime time.Time) PubRecSearchBy {
	return func(p *File) (int, error) {
		if p == nil {
			return -1, errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing publications file base object.")
		}

		if p.pubRecs == nil {
			return -1, nil
		}

		var (
			found  = false
			tm     = pubTime
			i      = 0
			pubRec *pdu.PublicationRec
		)
		for i, pubRec = range *p.pubRecs {
			recPubData, err := pubRec.PublicationData()
			if err != nil {
				return -1, errors.KsiErr(err).AppendMessage("Failed to extract publication data.")
			}

			recPubTime, err := recPubData.PublicationTime()
			if err != nil {
				return -1, errors.KsiErr(err).AppendMessage("Failed to extract publication time.")
			}

			if recPubTime.After(tm) {
				tm = recPubTime
				found = true
			}
		}
		if found {
			return i, nil
		}
		// No suitable publication found in the file.
		return -1, nil
	}
}

// PubRecSearchNearest searches for the publication that is published after given time and is closest to it.
func PubRecSearchNearest(pubTime time.Time) PubRecSearchBy {
	return func(p *File) (int, error) {
		if p == nil {
			return -1, errors.New(errors.KsiInvalidArgumentError).AppendMessage("Missing publications file base object.")
		}

		if p.pubRecs == nil {
			return -1, nil
		}
		for i, pubRec := range *p.pubRecs {
			recPubData, err := pubRec.PublicationData()
			if err != nil {
				return -1, errors.KsiErr(err).AppendMessage("Failed to extract publication data.")
			}

			recPubTime, err := recPubData.PublicationTime()
			if err != nil {
				return -1, errors.KsiErr(err).AppendMessage("Failed to extract publication time.")
			}

			if recPubTime.After(pubTime) {
				return i, nil
			}
		}
		// No suitable publication found in the file.
		return -1, nil
	}
}

// VerifyRecord verifies the calendar authentication record against publications file.
func (p *File) VerifyRecord(rec *pdu.CalendarAuthRec) error {
	if p == nil || rec == nil {
		return errors.New(errors.KsiInvalidArgumentError)
	}

	sigData, err := rec.SignatureData()
	if err != nil {
		return err
	}
	if sigData == nil {
		return errors.New(errors.KsiInvalidStateError).
			AppendMessage("Inconsistent calendar auth record.").
			AppendMessage("Missing signature data.")
	}
	certID, err := sigData.CertID()
	if err != nil {
		return err
	}
	sigType, err := sigData.SignatureType()
	if err != nil {
		return err
	}
	sigValue, err := sigData.SignatureValue()
	if err != nil {
		return err
	}

	pubData, err := rec.PublicationData()
	if err != nil {
		return err
	}
	raw, err := pubData.Bytes()
	if err != nil {
		return err
	}

	certRec, err := p.Certificate(certID)
	if err != nil {
		return err
	}
	if certRec == nil {
		return errors.New(errors.KsiInvalidStateError).
			AppendMessage("Suitable PKI certificate not found in publications file.")
	}
	cert, err := certRec.Cert()
	if err != nil {
		return err
	}

	x509cert, err := x509.ParseCertificate(cert)
	if err != nil || x509cert == nil {
		ksiErr := errors.New(errors.KsiCryptoFailure).AppendMessage("Failed to parse certificate.")
		if err != nil {
			_ = ksiErr.SetExtError(err)
		}
		return ksiErr
	}

	if err := certRec.VerifySigType(sigType); err != nil {
		return err
	}

	algo := x509cert.SignatureAlgorithm
	if err := x509cert.CheckSignature(algo, raw, sigValue); err != nil {
		return errors.New(errors.KsiInvalidPkiSignature).SetExtError(err).
			AppendMessage("Failed to verify signature.")
	}
	return nil
}

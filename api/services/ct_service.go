package services

import (
	"context"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"bitbucket.org/xoduxcrt/ssl/api/dto"
	"bitbucket.org/xoduxcrt/ssl/api/entities"
	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	x509 "github.com/google/certificate-transparency-go/x509"
	"github.com/jackc/pgx/v5"
)

type (
	CTService interface {
		Download(ctx context.Context, id string) (*dto.CTDownloadResponse, error)
		List(ctx context.Context, pageNum, pageSize int64) (*dto.CTListResponse, error)
		Search(ctx context.Context, searchBy, searchFor []string) (*dto.CTSearchResponse, error)
	}
	ctService struct {
		conn *pgx.Conn
	}
)

func NewCTService(conn *pgx.Conn) CTService {
	return &ctService{
		conn: conn,
	}
}

func (s *ctService) Download(ctx context.Context, id string) (*dto.CTDownloadResponse, error) {
	var rows pgx.Rows
	var err error
	if rows, err = s.conn.Query(ctx, "SELECT download_cert($1)", id); err != nil {
		return nil, errors.Join(err, dto.ErrQueryDownloadCert)
	}
	defer rows.Close()
	// Ensure we have at least one result
	if !rows.Next() {
		return nil, dto.ErrCertificateNotFound
	}

	var content string
	if err = rows.Scan(&content); err != nil {
		return nil, errors.Join(err, dto.ErrCertificateNotFound)
	}
	// Fill response
	resp := dto.CTDownloadResponse{
		PEMContent: []byte(content),
	}

	return &resp, nil
}

func (s *ctService) List(ctx context.Context, pageNum, pageSize int64) (*dto.CTListResponse, error) {
	var rows pgx.Rows
	var err error

	if rows, err = s.conn.Query(ctx,
		`SELECT
			c.ID ID,
			ca.NAME ISSUER_NAME,
			c.ISSUER_CA_ID,
			x509_notBefore(c.CERTIFICATE) NOT_BEFORE,
			x509_notAfter(c.CERTIFICATE) NOT_AFTER,
			encode(x509_serialNumber(c.CERTIFICATE), 'hex') SERIAL_NUMBER
		FROM certificate c, ca
		WHERE c.ID BETWEEN $1 AND $2 AND ca.ID = c.ISSUER_CA_ID
		ORDER BY ID ASC NULLS LAST`, (pageNum-1)*pageSize+1, pageNum*pageSize); err != nil {
		return nil, errors.Join(err, dto.ErrQueryDownloadCert)
	}
	defer rows.Close()

	var items []dto.CTListItem
	for rows.Next() {
		var itm dto.CTListItem

		err := rows.Scan(
			&itm.ID,
			&itm.IssuerName,
			&itm.IssuerCAID,
			&itm.NotBefore,
			&itm.NotAfter,
			&itm.SerialNumber,
		)
		if err != nil {
			return nil, errors.Join(err, dto.ErrCertificateNotFound)
		}

		items = append(items, itm)
	}

	// Fill response
	resp := dto.CTListResponse{
		Pagination: dto.Pagination{
			PageNum:    pageNum,
			PageSize:   pageSize,
		},
		Items: items,
	}

	return &resp, nil
}

func (s *ctService) Search(ctx context.Context, searchBy, searchFor []string) (*dto.CTSearchResponse, error) {
	rows, err := s.conn.Query(ctx, "SELECT test_apis($1, $2, $3)", "", searchBy, searchFor)
	if err != nil {
		return nil, errors.Join(err, dto.ErrQueryDownloadCert)
	}
	defer rows.Close()
	// Ensure we have at least one result
	if !rows.Next() {
		return nil, dto.ErrQueryDownloadCert
	}

	var content string
	if err = rows.Scan(&content); err != nil {
		return nil, errors.Join(err, dto.ErrSearchResultNotFound)
	}

	searchType := dto.IdentitySearch
	for _, sb := range searchBy {
		if _, exists := dto.CertificateSearchFields[sb]; exists {
			searchType = dto.CertificateSearch
			break
		}
		if sb == "caid" {
			searchType = dto.SpecificCASearch
			break
		}
		if sb == "caname" {
			searchType = dto.MultipleCASearch
			break
		}
	}

	switch searchType {
	case dto.CertificateSearch:
		searchRes := map[string]interface{}{}
		if err = json.Unmarshal([]byte(content), &searchRes); err != nil {
			return nil, errors.Join(err, dto.ErrUnmarshalSearchResult)
		}

		cert, err := s.parseX509Text(searchRes["certificate"].(string))
		if err != nil {
			return nil, errors.Join(err, dto.ErrParseX509Text)
		}

		searchRes["certificate"] = cert
		// Fill response
		resp := dto.CTSearchResponse{
			CertificateContent: searchRes,
		}

		return &resp, nil
	case dto.SpecificCASearch:
		searchRes := map[string]interface{}{}
		if err = json.Unmarshal([]byte(content), &searchRes); err != nil {
			return nil, errors.Join(err, dto.ErrUnmarshalSearchResult)
		}

		cert, err := s.parseX509Text(searchRes["ca_name_key"].(string))
		if err != nil {
			return nil, errors.Join(err, dto.ErrParseX509Text)
		}

		caNameKey := make(map[string]interface{})

		if data, exists := cert["data"].(map[string]interface{}); exists {
			if subject, exists := data["subject"].(map[string]interface{}); exists {
				caNameKey["subject"] = subject
			}
			if spki, exists := data["subject_public_key_info"].(map[string]interface{}); exists {
				caNameKey["subject_public_key_info"] = spki
			}
		}

		searchRes["ca_name_key"] = caNameKey
		// Fill response
		resp := dto.CTSearchResponse{
			SpecificCAContent: searchRes,
		}

		return &resp, nil
	case dto.MultipleCASearch:
		searchRes := []map[string]interface{}{}
		if err = json.Unmarshal([]byte(content), &searchRes); err != nil {
			return nil, errors.Join(err, dto.ErrUnmarshalSearchResult)
		}
		// Fill response
		resp := dto.CTSearchResponse{
			MultipleCAContent: searchRes,
		}

		return &resp, nil
	default:
		searchRes := []map[string]interface{}{}
		if err = json.Unmarshal([]byte(content), &searchRes); err != nil {
			return nil, errors.Join(err, dto.ErrUnmarshalSearchResult)
		}
		// Fill response
		resp := dto.CTSearchResponse{
			IdentityContent: searchRes,
		}

		return &resp, nil
	}
}

func (s *ctService) parseX509Text(certHex string) (map[string]interface{}, error) {
	certBytes, err := hex.DecodeString(certHex)
	if err != nil {
		return nil, errors.Join(err, dto.ErrHexDecodeString)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, errors.Join(err, dto.ErrX509ParseCertificate)
	}

	version := cert.Version + 1
	var serialNumber *string = nil
	if cert.SerialNumber != nil {
		sn := fmt.Sprintf("%x", cert.SerialNumber)
		serialNumber = &sn
	}

	signatureAlgorithm := cert.SignatureAlgorithm.String()
	spki := entities.SubjectPublicKeyInfo{
		Algorithm: cert.PublicKeyAlgorithm.String(),
	}

	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		spki.RSA = s.parseRSAInfo(cert)
	case x509.DSA:
		spki.DSA = s.parseDSAInfo(cert)
	case x509.ECDSA:
		spki.ECDSA = s.parseECDSAInfo(cert)
	default:
		spki.Unknown = s.parseUnknownInfo(cert)
	}

	extensions := &entities.X509v3Extensions{}

	keyUsages := map[int]string{}
	keyUsages[int(x509.KeyUsageDigitalSignature)] = "Digital Signature"
	keyUsages[int(x509.KeyUsageContentCommitment)] = "Content Commitment"
	keyUsages[int(x509.KeyUsageKeyEncipherment)] = "Key Encipherment"
	keyUsages[int(x509.KeyUsageDataEncipherment)] = "Data Encipherment"
	keyUsages[int(x509.KeyUsageKeyAgreement)] = "Key Agreement"
	keyUsages[int(x509.KeyUsageCertSign)] = "Certificate Sign"
	keyUsages[int(x509.KeyUsageCRLSign)] = "CRL Sign"
	keyUsages[int(x509.KeyUsageEncipherOnly)] = "Encipher Only"
	keyUsages[int(x509.KeyUsageDecipherOnly)] = "Decipher Only"
	for k, v := range keyUsages {
		if cert.KeyUsage&x509.KeyUsage(k) != 0 {
			extensions.KeyUsage.Usages = append(extensions.KeyUsage.Usages, v)
		}
	}
	if len(extensions.KeyUsage.Usages) > 0 {
		extensions.KeyUsage.IsCritical = true
	}

	extKeyUsages := map[int]string{}
	extKeyUsages[int(x509.ExtKeyUsageAny)] = "Any"
	extKeyUsages[int(x509.ExtKeyUsageServerAuth)] = "TLS Web Server Authentication"
	extKeyUsages[int(x509.ExtKeyUsageClientAuth)] = "TLS Web Client Authentication"
	extKeyUsages[int(x509.ExtKeyUsageCodeSigning)] = "Code Signing"
	extKeyUsages[int(x509.ExtKeyUsageEmailProtection)] = "Email Protection"
	extKeyUsages[int(x509.ExtKeyUsageIPSECEndSystem)] = "IPSEC End System"
	extKeyUsages[int(x509.ExtKeyUsageIPSECTunnel)] = "IPSEC Tunnel"
	extKeyUsages[int(x509.ExtKeyUsageIPSECUser)] = "IPSEC User"
	extKeyUsages[int(x509.ExtKeyUsageTimeStamping)] = "Timestamping"
	extKeyUsages[int(x509.ExtKeyUsageOCSPSigning)] = "OCSP Signing"
	extKeyUsages[int(x509.ExtKeyUsageMicrosoftServerGatedCrypto)] = "Microsoft Server Gated Crypto"
	extKeyUsages[int(x509.ExtKeyUsageNetscapeServerGatedCrypto)] = "Netscape Server Gated Crypto"
	extKeyUsages[int(x509.ExtKeyUsageMicrosoftCommercialCodeSigning)] = "Microsoft Commercial Code Signing"
	extKeyUsages[int(x509.ExtKeyUsageMicrosoftKernelCodeSigning)] = "Microsoft Kernel Code Signing"
	extKeyUsages[int(x509.ExtKeyUsageCertificateTransparency)] = "Certificate Transparency"
	for _, v := range cert.ExtKeyUsage {
		extensions.ExtendedKeyUsage = append(extensions.ExtendedKeyUsage, extKeyUsages[int(v)])
	}

	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(x509.OIDExtensionCTPoison):
			extensions.CTPrecertificatePosion = &entities.CTPrecertificatePosion{
				IsCritical: true,
			}
		}
	}
	if cert.BasicConstraintsValid {
		extensions.BasicConstraints = entities.BasicConstraints{
			IsCA:       cert.IsCA,
			IsCritical: true,
		}

		pathLen := cert.MaxPathLen
		extensions.BasicConstraints.PathLen = &pathLen
	}
	if cert.SubjectKeyId != nil {
		subjectKeyId := s.formatSignature(cert.SubjectKeyId)
		extensions.SubjectKeyIdentifier = &subjectKeyId
	}
	if cert.AuthorityKeyId != nil {
		authorityKeyId := s.formatSignature(cert.AuthorityKeyId)
		extensions.AuthorityKeyIdentifier = &authorityKeyId
	}
	extensions.AuthorityInfoAccess = append(extensions.AuthorityInfoAccess, cert.IssuingCertificateURL...)
	extensions.SubjectAlternativeName = entities.SubjectAlternativeName{
		DNSNames:       cert.DNSNames,
		EmailAddresses: cert.EmailAddresses,
		IPAddresses:    cert.IPAddresses,
		URIs:           cert.URIs,
	}
	for _, p := range cert.PolicyIdentifiers {
		extensions.CertificatePolicies = append(extensions.CertificatePolicies, p.String())
	}
	extensions.CRLDistributionPoints = append(extensions.CRLDistributionPoints, cert.CRLDistributionPoints...)

	if len(cert.SCTList.SCTList) > 0 {
		for _, s := range cert.SCTList.SCTList {
			var rawSct ctgo.SignedCertificateTimestamp
			if _, err := tls.Unmarshal(s.Val, &rawSct); err != nil {
				continue
			}

			sct := entities.SignedCertificateTimestamp{
				Version:            int(rawSct.SCTVersion),
				LogID:              fmt.Sprintf("%x", rawSct.LogID.KeyID),
				Timestamp:          ctgo.TimestampToTime(rawSct.Timestamp).UTC(),
				SignatureAlgorithm: rawSct.Signature.Algorithm.Signature.String(),
				SignatureValue:     fmt.Sprintf("%x", rawSct.Signature.Signature),
			}

			if rawSct.Extensions != nil {
				sctExt := fmt.Sprintf("%x", rawSct.Extensions)
				sct.Extensions = &sctExt
			}

			extensions.CTPrecertificateSCTs = append(extensions.CTPrecertificateSCTs, sct)
		}
	}
	certificate := entities.Certificate{
		Data: entities.Data{
			Version:            &version,
			SerialNumber:       serialNumber,
			SignatureAlgorithm: &signatureAlgorithm,
			Issuer: &entities.CA{
				CommonName:       cert.Issuer.CommonName,
				OrganizationName: cert.Issuer.Organization,
				CountryName:      cert.Issuer.Country,
			},
			Validity: &entities.Validity{
				NotBefore: cert.NotBefore,
				NotAfter:  cert.NotAfter,
			},
			Subject: entities.CA{
				CommonName:       cert.Issuer.CommonName,
				OrganizationName: cert.Issuer.Organization,
				CountryName:      cert.Issuer.Country,
			},
			SubjectPublicKeyInfo: spki,
			X509v3Extensions:     extensions,
		},
		SignatureAlgorithm: signatureAlgorithm,
		SignatureValue:     hex.EncodeToString(cert.Signature),
	}

	bytes, err := json.Marshal(certificate)
	if err != nil {
		return nil, errors.Join(err, dto.ErrMarhsalCertificate)
	}

	resp := make(map[string]interface{})
	if err := json.Unmarshal(bytes, &resp); err != nil {
		return nil, errors.Join(err, dto.ErrUnmarhsalCertificate)
	}

	return resp, nil
}

func (s *ctService) getCurveOID(curve ecdh.Curve) (asn1.ObjectIdentifier, error) {
	switch curve {
	case ecdh.P256():
		return pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}}.Algorithm, nil
	case ecdh.P384():
		return pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 132, 0, 34}}.Algorithm, nil
	case ecdh.P521():
		return pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 132, 0, 35}}.Algorithm, nil
	default:
		return nil, dto.ErrCurveUnsupported
	}
}

func (s *ctService) formatSignature(sig []byte) string {
	var builder strings.Builder
	for _, b := range sig {
		builder.WriteString(fmt.Sprintf("%02x", b))
	}
	return builder.String()
}

func (s *ctService) parseRSAInfo(cert *x509.Certificate) *entities.PubKeyAlgoRSA {
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		rsaInfo := &entities.PubKeyAlgoRSA{
			Size:     pub.Size() * 8,
			Modulus:  fmt.Sprintf("%x", pub.N.Bytes()),
			Exponent: fmt.Sprintf("%d", pub.E),
		}
		return rsaInfo
	}
	return nil
}

func (s *ctService) parseDSAInfo(cert *x509.Certificate) *entities.PubKeyAlgoDSA {
	if pub, ok := cert.PublicKey.(*dsa.PublicKey); ok {
		dsaInfo := &entities.PubKeyAlgoDSA{
			L:         pub.P.BitLen(),
			N:         pub.Q.BitLen(),
			PublicKey: fmt.Sprintf("%x", pub.Y.Bytes()),
			P:         fmt.Sprintf("%x", pub.P.Bytes()),
			Q:         fmt.Sprintf("%x", pub.Q.Bytes()),
			G:         fmt.Sprintf("%x", pub.G.Bytes()),
		}
		return dsaInfo
	}
	return nil
}

func (s *ctService) parseECDSAInfo(cert *x509.Certificate) *entities.PubKeyAlgoECDSA {
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		ecdsaInfo := &entities.PubKeyAlgoECDSA{
			NISTCurve: pub.Curve.Params().Name,
		}
		// Convert to ECDH public key
		ecdhPubKey, err := pub.ECDH()
		if err == nil {
			pubKey := fmt.Sprintf("%x", ecdhPubKey.Bytes())
			ecdsaInfo.PublicKey = &pubKey

			asn1Oid, err := s.getCurveOID(ecdhPubKey.Curve())
			if err == nil {
				asn10Id := asn1Oid.String()
				ecdsaInfo.ASN1OID = &asn10Id
			}
			ecdsaInfo.Size = pub.Curve.Params().BitSize
		}
		return ecdsaInfo
	}
	return nil
}

func (s *ctService) parseUnknownInfo(cert *x509.Certificate) *entities.PubKeyAlgoUnknown {
	spki := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil
	}

	unknownInfo := &entities.PubKeyAlgoUnknown{
		Size:      len(spki.PublicKey.Bytes) * 8,
		PublicKey: fmt.Sprintf("%x", spki.PublicKey.Bytes),
	}

	return unknownInfo
}

package entities

import (
	"net"
	"net/url"
	"time"
)

type (
	Certificate struct {
		Data               Data   `json:"data"`
		SignatureAlgorithm string `json:"signature_algorithm"`
		SignatureValue     string `json:"signature_value"`
	}

	Data struct {
		Version              *int                 `json:"version,omitempty"`
		SerialNumber         *string              `json:"serial_number,omitempty"`
		SignatureAlgorithm   *string              `json:"signature_algorithm,omitempty"`
		Issuer               *CA                  `json:"issuer,omitempty"`
		Validity             *Validity            `json:"validity,omitempty"`
		Subject              CA                   `json:"subject"`
		SubjectPublicKeyInfo SubjectPublicKeyInfo `json:"subject_public_key_info"`
		X509v3Extensions     *X509v3Extensions    `json:"x509v3_extensions,omitempty"`
	}

	CA struct {
		CommonName       string   `json:"common_name"`
		OrganizationName []string `json:"organization_name,omitempty"`
		CountryName      []string `json:"country_name,omitempty"`
	}

	Validity struct {
		NotBefore time.Time `json:"not_before"`
		NotAfter  time.Time `json:"not_after"`
	}

	SubjectPublicKeyInfo struct {
		Algorithm string             `json:"algorithm"`
		RSA       *PubKeyAlgoRSA     `json:"rsa,omitempty"`
		DSA       *PubKeyAlgoDSA     `json:"dsa,omitempty"`
		ECDSA     *PubKeyAlgoECDSA   `json:"ecdsa,omitempty"`
		Unknown   *PubKeyAlgoUnknown `json:"unknown,omitempty"`
	}

	PubKeyAlgoRSA struct {
		Size     int    `json:"size"`
		Modulus  string `json:"modulus"`
		Exponent string `json:"exponent"`
	}

	PubKeyAlgoDSA struct {
		L         int    `json:"l"`
		N         int    `json:"n"`
		PublicKey string `json:"public_key"`
		P         string `json:"p"`
		Q         string `json:"q"`
		G         string `json:"g"`
	}

	PubKeyAlgoECDSA struct {
		Size      int     `json:"size"`
		PublicKey *string `json:"public_key,omitempty"`
		ASN1OID   *string `json:"asn1_oid,omitempty"`
		NISTCurve string  `json:"nist_curve"`
	}

	PubKeyAlgoUnknown struct {
		Size      int    `json:"size"`
		PublicKey string `json:"public_key"`
	}

	X509v3Extensions struct {
		KeyUsage               KeyUsage                     `json:"key_usage"`
		ExtendedKeyUsage       []string                     `json:"extended_key_usage,omitempty"`
		BasicConstraints       BasicConstraints             `json:"basic_constraints"`
		SubjectKeyIdentifier   *string                      `json:"subject_key_identifier,omitempty"`
		AuthorityKeyIdentifier *string                      `json:"authority_key_identifier,omitempty"`
		AuthorityInfoAccess    []string                     `json:"authority_info_access,omitempty"`
		SubjectAlternativeName SubjectAlternativeName       `json:"subject_alternative_name"`
		CertificatePolicies    []string                     `json:"certificate_policies,omitempty"`
		CRLDistributionPoints  []string                     `json:"crl_distribution_points,omitempty"`
		CTPrecertificatePosion *CTPrecertificatePosion      `json:"ct_precertificate_poison,omitempty"`
		CTPrecertificateSCTs   []SignedCertificateTimestamp `json:"ct_precertificate_scts,omitempty"`
	}

	KeyUsage struct {
		IsCritical bool     `json:"is_criticial"`
		Usages     []string `json:"usages,omitempty"`
	}

	BasicConstraints struct {
		IsCritical bool `json:"is_criticial"`
		IsCA       bool `json:"is_ca"`
		PathLen    *int `json:"path_len,omitempty"`
	}

	SubjectAlternativeName struct {
		DNSNames       []string   `json:"dns_names,omitempty"`
		EmailAddresses []string   `json:"email_addresses,omitempty"`
		IPAddresses    []net.IP   `json:"ip_addresses,omitempty"`
		URIs           []*url.URL `json:"uris,omitempty"`
	}

	CTPrecertificatePosion struct {
		IsCritical bool `json:"is_criticial"`
	}

	SignedCertificateTimestamp struct {
		Version            int       `json:"version"`
		LogID              string    `json:"log_id"`
		Timestamp          time.Time `json:"timestamp"`
		Extensions         *string   `json:"extensions,omitempty"`
		SignatureAlgorithm string    `json:"signature_algorithm"`
		SignatureValue     string    `json:"signature_value"`
	}
)

package dto

import "time"

type (
	CTDownloadResponse struct {
		PEMContent []byte `json:"pem_content"`
	}

	CTListResponse struct {
		Items      []CTListItem `json:"items,omitempty"`
		Pagination Pagination   `json:"pagination"`
	}

	CTListItem struct {
		ID           int64     `json:"id"`
		IssuerName   string    `json:"issuer_name"`
		IssuerCAID   int64     `json:"issuer_ca_id"`
		NotBefore    time.Time `json:"not_before"`
		NotAfter     time.Time `json:"not_after"`
		SerialNumber string    `json:"serial_number"`
	}

	CTSearchResponse struct {
		CertificateContent map[string]interface{}   `json:"certificate_content,omitempty"`
		IdentityContent    []map[string]interface{} `json:"identity_content,omitempty"`
		SpecificCAContent  map[string]interface{}   `json:"specific_ca_content,omitempty"`
		MultipleCAContent  []map[string]interface{} `json:"multiple_ca_content,omitempty"`
	}

	CTSearchType string
)

const (
	CertificateSearch = CTSearchType("certificate")
	IdentitySearch    = CTSearchType("identity")
	SpecificCASearch  = CTSearchType("specific_ca")
	MultipleCASearch  = CTSearchType("multiple_ca")
)

var CTSearchFields = []string{
	"c", "sha1", "sha256",
	"ctid", "ca", "caid", "caname", "serial", "ski", "spkisha1", "spkisha256",
	"cnlspkisha256", "subjectsha1", "identity", "commonname", "cn", "emailaddress",
	"e", "organizationalunitname", "ou", "organizationname", "o", "dnsname",
	"domain", "rfc822name", "esan", "ipaddress", "ip", "q", "a", "s", "cablint",
	"x509lint", "zlint", "keylint", "lint", "dir", "sort", "group",
}

var CertificateSearchFields = map[string]bool{
	"id":     false,
	"sha1":   false,
	"sha256": false,
}

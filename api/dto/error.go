package dto

import "errors"

var (
	// Middleware level errors
	ErrTooManyRequests = errors.New("too_many_requests")
	ErrTokenNotValid   = errors.New("token_not_valid")
	ErrNotInWhitelist  = errors.New("not_in_whitelist")
	// Handler level errors
	ErrGetQueryParam = errors.New("failed_get_query_param")
	ErrServer        = errors.New("server_error")
	ErrParamNotValid = errors.New("param_not_valid")
	// Service level errors
	ErrQueryDownloadCert     = errors.New("failed_query_download_cert")
	ErrCertificateNotFound   = errors.New("failed_certificate_not_found")
	ErrSearchResultNotFound  = errors.New("failed_search_result_not_found")
	ErrUnmarshalSearchResult = errors.New("failed_unmarshal_search_result")
	ErrParseX509Text         = errors.New("failed_parse_x509_text")
	ErrHexDecodeString       = errors.New("failed_hex_decode_string")
	ErrX509ParseCertificate  = errors.New("failed_x509_parse_certificate")
	ErrMarhsalCertificate    = errors.New("failed_marshal_certificate")
	ErrUnmarhsalCertificate  = errors.New("failed_unmarshal_certificate")
	ErrCurveUnsupported      = errors.New("curve_unsupported")
)

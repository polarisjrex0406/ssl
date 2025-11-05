package dto

const (
	// Success
	MESSAGE_SUCCESS = "Success"

	// Failed
	MESSAGE_FAILED                   = "Failed"
	MESSAGE_FAILED_TOO_MANY_REQUESTS = "Too many requests"
	MESSAGE_FAILED_TOKEN_NOT_VALID   = "Token not valid"
	MESSAGE_FAILED_NOT_IN_WHITELIST  = "Not in whitelist"
)

type (
	Pagination struct {
		PageNum  int64 `json:"page_num"`
		PageSize int64 `json:"page_size"`
	}
)

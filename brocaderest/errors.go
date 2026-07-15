package brocaderest

// Sanitized error codes. Never wrap upstream messages that could leak URLs,
// headers, or response bodies containing secrets. Callers translate the code
// to human copy at the UI/audit layer.
const (
	ErrCodeUnknownOperation    = "unknown_operation"
	ErrCodeInvalidParameter    = "invalid_parameter"
	ErrCodeTransportUnsupported = "transport_unsupported"
	ErrCodeLabModeRequired     = "lab_mode_required"
	ErrCodeTLSUntrusted        = "tls_untrusted"
	ErrCodeRESTAuthFailed      = "rest_auth_failed"
	ErrCodeRESTConnectionFailed = "rest_connection_failed"
	ErrCodeRESTTimeout         = "rest_timeout"
	ErrCodeRESTHTTPError       = "rest_http_error"
	ErrCodeResponseTooLarge    = "response_too_large"
	ErrCodeRedirectRefused     = "redirect_refused"
	ErrCodeMissingPassword     = "missing_rest_password"
	ErrCodeReadOnlyProbeFailed = "read_only_probe_failed"
)

// Error is the sanitized error type returned by Client.Do. Only Code is
// intended for structured programmatic handling; Detail is a short, non-secret
// hint safe to log and surface to operators.
type Error struct {
	Code   string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

func newErr(code, detail string) *Error { return &Error{Code: code, Detail: detail} }

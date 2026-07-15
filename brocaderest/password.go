package brocaderest

import (
	"fmt"
	"io/fs"
	"os"
)

// readPassword loads the REST password from a 0600/0400 file. The caller is
// expected to zeroBytes() the returned slice as soon as the credential has
// been consumed. Errors are sanitized — never include file contents.
func readPassword(path string) ([]byte, *Error) {
	if path == "" {
		return nil, newErr(ErrCodeMissingPassword, "password_file not configured")
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, newErr(ErrCodeMissingPassword, "password_file unreadable")
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, newErr(ErrCodeMissingPassword, "password_file must not be a symlink")
	}
	if !fi.Mode().IsRegular() {
		return nil, newErr(ErrCodeMissingPassword, "password_file must be a regular file")
	}
	perm := fi.Mode().Perm()
	if perm&0o077 != 0 {
		return nil, newErr(ErrCodeMissingPassword, fmt.Sprintf("password_file permissions %#o are too permissive; use 0600 or 0400", perm))
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, newErr(ErrCodeMissingPassword, "password_file read failed")
	}
	// Trim a single trailing newline if present, without allocating a new
	// large buffer.
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b[n-1] = 0
		b = b[:n-1]
	}
	if len(b) == 0 {
		return nil, newErr(ErrCodeMissingPassword, "password_file is empty")
	}
	return b, nil
}

// zeroBytes best-effort clears a credential buffer. Go's runtime may still hold
// copies (e.g. inside strings promoted from []byte); this is a defense-in-depth
// hygiene practice, not cryptographic memory erasure.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

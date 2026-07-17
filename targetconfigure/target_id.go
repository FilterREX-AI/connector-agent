// Authoritative target-ID resolution and canonicalization for targets.json.
//
// Option-B identity model (preview.13):
//
//   - outer targets.json map key = local profile identifier / CLI selector
//   - `target_id`               = authoritative application target-profile UUID
//   - heartbeat per_target key  = canonical target_id UUID (lowercase)
//
// This file exposes the ONE resolver used by both the CLI (`target configure`,
// `target probe`) and the readiness-snapshot loader consumed by the heartbeat.
// Keeping resolution in one place prevents "profile-name must secretly equal
// UUID" invariants from re-emerging across surfaces.
package targetconfigure

import (
	"errors"
	"strings"
)

// Stable, code-visible sentinel errors so callers can distinguish operator
// misconfiguration ("target_id required") from a corrupt record ("invalid").
var (
	ErrTargetIDMissing = errors.New("target_id_missing")
	ErrInvalidTargetID = errors.New("invalid_target_id")
)

// canonicalUUID returns the lowercase hyphenated form when s parses as a
// canonical RFC 4122 v1–v5 UUID (matches isProfileUUID's regex). Returns
// "" when s is not a UUID.
func canonicalUUID(s string) string {
	s = strings.TrimSpace(s)
	if !profileUUIDRe.MatchString(s) {
		return ""
	}
	return strings.ToLower(s)
}

// EffectiveTargetID resolves the authoritative application target UUID for a
// targets.json record. Rules (in order):
//
//  1. rec.TargetID set and a valid UUID → return its canonical (lowercase)
//     form.
//  2. rec.TargetID set but not a valid UUID → ErrInvalidTargetID (fail closed;
//     never publish anything for this record).
//  3. rec.TargetID empty and profileName is itself a valid UUID → return the
//     canonical form of the profile name (backward-compat with existing
//     configs whose outer key is the UUID).
//  4. Otherwise → ErrTargetIDMissing (do not publish under an arbitrary
//     profile label like "faba").
//
// The returned string is always the canonical lowercase UUID and safe to use
// as both a heartbeat map key and a filesystem-adjacent identifier.
func EffectiveTargetID(profileName string, rec *targetRecord) (string, error) {
	if rec == nil {
		return "", ErrTargetIDMissing
	}
	if strings.TrimSpace(rec.TargetID) != "" {
		id := canonicalUUID(rec.TargetID)
		if id == "" {
			return "", ErrInvalidTargetID
		}
		return id, nil
	}
	if id := canonicalUUID(profileName); id != "" {
		return id, nil
	}
	return "", ErrTargetIDMissing
}

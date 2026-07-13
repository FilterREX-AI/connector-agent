package evidencebundle

// ProfileCommand is a read-only, exported view of one entry in the embedded
// Brocade command profile. Producers (e.g. the brocadecli SSH capture module)
// use this to derive the *exact* set of read-only commands to run — the profile
// is the single source of truth shared with the Python collector and the TS
// catalog. There is deliberately no way to inject a command that is not here.
type ProfileCommand struct {
	// ID is the canonical command label written to manifest.files[].command.
	ID string
	// Exec is the actual read-only command string to run over SSH. It may
	// contain the "{port_range}" placeholder, substituted by the producer.
	Exec string
	// Filename is the canonical bundle filename for this command's output.
	Filename string
	// SupportLevel is "parsed" or "supporting_only" (informational for
	// producers; the importer derives the authoritative value from the catalog).
	SupportLevel string
	// Importance is "required" | "recommended" | "optional".
	Importance string
}

// ProfileCommands returns the embedded read-only Brocade command profile as an
// ordered slice. The order matches the profile file. It returns an error only
// if the embedded JSON is corrupt (a build-time invariant).
func ProfileCommands() ([]ProfileCommand, error) {
	p, _, err := loadEmbeddedProfile()
	if err != nil {
		return nil, err
	}
	out := make([]ProfileCommand, 0, len(p.Commands))
	for _, c := range p.Commands {
		out = append(out, ProfileCommand{
			ID:           c.ID,
			Exec:         c.Exec,
			Filename:     c.Filename,
			SupportLevel: c.SupportLevel,
			Importance:   c.Importance,
		})
	}
	return out, nil
}

// DefaultPortRange returns the profile's default port range (defaults.port_range)
// used to substitute the "{port_range}" placeholder in Exec strings. It returns
// "" when the profile declares no default.
func DefaultPortRange() string {
	p, _, err := loadEmbeddedProfile()
	if err != nil {
		return ""
	}
	if p.Defaults == nil {
		return ""
	}
	return p.Defaults["port_range"]
}

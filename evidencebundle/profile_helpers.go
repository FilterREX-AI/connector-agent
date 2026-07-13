package evidencebundle

// CommandForFilename resolves a bundle filename (e.g. "switchshow.txt") back to
// its canonical command id (e.g. "switchshow") using the embedded profile.
// Producers use this to label captured files consistently with the contract.
func CommandForFilename(filename string) (command string, ok bool) {
	profile, _, err := loadEmbeddedProfile()
	if err != nil {
		return "", false
	}
	for _, c := range profile.Commands {
		if c.Filename == filename {
			return c.ID, true
		}
	}
	return "", false
}

// FilenameForCommand resolves a canonical command id to its bundle filename.
func FilenameForCommand(command string) (filename string, ok bool) {
	_, byID, err := loadEmbeddedProfile()
	if err != nil {
		return "", false
	}
	if c, present := byID[command]; present {
		return c.Filename, true
	}
	return "", false
}

// SupportLevelForCommand returns the profile support level ("parsed" or
// "supporting_only") for a command id. Informational only — it is intentionally
// NOT written into the manifest (the importer derives it from the catalog).
func SupportLevelForCommand(command string) (level string, ok bool) {
	_, byID, err := loadEmbeddedProfile()
	if err != nil {
		return "", false
	}
	if c, present := byID[command]; present {
		return c.SupportLevel, true
	}
	return "", false
}

// ProfileVersion returns the embedded profile's version string.
func ProfileVersion() string {
	profile, _, err := loadEmbeddedProfile()
	if err != nil {
		return ""
	}
	return profile.ProfileVersion
}

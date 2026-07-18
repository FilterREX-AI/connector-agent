package targetconfigure

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RunDoctor is the local operator diagnostic for daemon-visible Brocade target
// configuration. It is intentionally read-only and secret-free: it reports
// whether targets.json, the selected target UUID, and the referenced key files
// are visible from THIS process/container, without printing addresses, users,
// key paths, or file contents.
func RunDoctor(args []string) int {
	fs := flag.NewFlagSet("target doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configDir := fs.String("config-dir", "/etc/filterrex", "Connector daemon config directory used for legacy fallback resolution.")
	targetsDir := fs.String("targets-dir", "", "Explicit target-config directory. Defaults to FILTERREX_BROCADE_TARGETS_DIR, then /etc/filterrex/targets.")
	targetID := fs.String("target-id", "", "Application target-profile UUID to verify inside targets.json.")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*targetID) == "" {
		fmt.Fprintln(os.Stderr, "target doctor: --target-id is required.")
		return 2
	}
	canonicalTargetID := canonicalUUID(*targetID)
	if canonicalTargetID == "" {
		fmt.Fprintln(os.Stderr, "target doctor: --target-id must be a valid target-profile UUID.")
		return 2
	}

	envOverride := os.Getenv("FILTERREX_BROCADE_TARGETS_DIR")
	if strings.TrimSpace(*targetsDir) != "" {
		envOverride = *targetsDir
	}
	resolution := ResolveTargetConfigStore(envOverride, *configDir)
	target := InspectTargetConfigForTarget(resolution.Dir, canonicalTargetID)
	runtimeDir := strings.TrimSpace(os.Getenv("FILTERREX_BROCADE_RUNTIME_STATE_DIR"))
	if runtimeDir == "" {
		runtimeDir = filepath.Join(*configDir, "state")
	}
	runtimePresent, runtimeReadable := filePresence(filepath.Join(runtimeDir, runtimeReadinessFile))

	fmt.Println("Brocade target doctor")
	printDoctorLine("Target config source", resolution.Source)
	printDoctorLine("Target config directory present", boolWord(resolution.DirectoryPresent))
	printDoctorLine("Target config directory readable", boolWord(resolution.DirectoryReadable))
	printDoctorLine("targets.json present", boolWord(resolution.FilePresent))
	printDoctorLine("targets.json readable", boolWord(resolution.FileReadable))
	printDoctorLine("targets.json parsed", boolWord(resolution.ParseSuccessful))
	printDoctorLine("records loaded", fmt.Sprintf("%d", resolution.RecordsLoaded))
	printDoctorLine("target UUID", canonicalTargetID)
	printDoctorLine("target record matches", fmt.Sprintf("%d", target.TargetMatchCount))
	printDoctorLine("target profile found", boolWord(target.TargetProfileFound))
	printDoctorLine("SSH username present", boolWord(target.SSHUsernamePresent))
	printDoctorLine("private key present", boolWord(target.PrivateKeyPresent))
	printDoctorLine("private key readable", boolWord(target.PrivateKeyReadable))
	printDoctorLine("public key present", boolWord(target.PublicKeyPresent))
	printDoctorLine("public key readable", boolWord(target.PublicKeyReadable))
	printDoctorLine("known_hosts present", boolWord(target.KnownHostsPresent))
	printDoctorLine("known_hosts readable", boolWord(target.KnownHostsReadable))
	printDoctorLine("known_hosts entry found", boolWord(target.KnownHostsEntryFound))
	printDoctorLine("runtime readiness present", boolWord(runtimePresent))
	printDoctorLine("runtime readiness readable", boolWord(runtimeReadable))
	printDoctorLine("status", target.ResolvedStatus)

	if resolution.Warning != "" {
		printDoctorLine("warning", resolution.Warning)
	}
	printDoctorHint(target.ResolvedStatus)
	if target.ResolvedStatus != TargetConfigOK {
		return 1
	}
	return 0
}

func printDoctorLine(label, value string) {
	fmt.Printf("  %-34s %s\n", label, value)
}

func boolWord(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func printDoctorHint(status string) {
	switch status {
	case TargetConfigMissing:
		fmt.Println("Next: recreate the daemon container with /opt/filterrex/secure mounted read-only at /etc/filterrex/targets, then run target configure if targets.json is still absent.")
	case TargetConfigUnreadable:
		fmt.Println("Next: fix filesystem permissions so the daemon container can read targets.json and its parent directory.")
	case TargetConfigNoTarget:
		fmt.Println("Next: rerun target configure with --target-id set to the application target UUID shown above, then recreate or restart the daemon container.")
	case TargetConfigDuplicate:
		fmt.Println("Next: remove duplicate records that resolve to the same application target UUID; the agent drops ambiguous readiness.")
	case TargetConfigKeyMissing:
		fmt.Println("Next: rerun target configure for this target and verify the key and known_hosts files are on the same mounted secure directory.")
	case TargetConfigKeyUnreadable:
		fmt.Println("Next: fix permissions so the daemon container can read the managed private key file.")
	case TargetConfigKnownHostsMissing:
		fmt.Println("Next: rerun target configure and complete host-key enrollment so known_hosts is written into the secure directory.")
	case TargetConfigHostKeyMissing:
		fmt.Println("Next: rerun target configure and confirm the switch host-key fingerprint for this target address.")
	case TargetConfigUnmanagedArtifact:
		fmt.Println("Next: upgrade to the path-resolution release, then rerun target configure so managed artifact paths are relative to the secure directory.")
	}
}

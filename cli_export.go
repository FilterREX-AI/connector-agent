package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/filterrex-ai/connector-agent/brocadeexport"
)

// runExportBrocadeBundleCLI implements the local `export-brocade-bundle`
// operation. It is a deliberate operator invocation on the agent host: it reads
// a local JSON config, runs the read-only SSH capture + Evidence Bundle v1.0
// writer, writes an immutable timestamped ZIP locally, appends a local audit
// record, and prints machine-readable JSON to stdout.
//
// It never uploads, never reaches the cloud, and is not wired to the relay or
// the local API. On any validation/export failure it prints an error JSON and
// exits non-zero.
func runExportBrocadeBundleCLI(args []string) {
	// Ensure the audit logger exists for this short-lived process.
	configLevel := os.Getenv("LOG_LEVEL")
	if configLevel == "" {
		configLevel = "info"
	}
	InitAuditLogger(configLevel)

	fs := flag.NewFlagSet("export-brocade-bundle", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to the local Brocade export config JSON (required)")
	outDir := fs.String("out", "", "override artifact output directory (optional)")
	if err := fs.Parse(args); err != nil {
		fmt.Println(brocadeexport.ErrorJSON(err))
		os.Exit(2)
	}
	if *configPath == "" {
		err := fmt.Errorf("--config is required")
		fmt.Println(brocadeexport.ErrorJSON(err))
		os.Exit(2)
	}

	cfg, err := brocadeexport.LoadConfig(*configPath)
	if err != nil {
		fmt.Println(brocadeexport.ErrorJSON(err))
		os.Exit(1)
	}
	if *outDir != "" {
		cfg.ArtifactDir = *outDir
	}

	req := brocadeexport.RequestMeta{
		RequesterType: "local_cli",
		Requester:     "connector-agent export-brocade-bundle",
		ConfigPath:    *configPath,
	}

	res, err := brocadeexport.RunExportWithSSH(context.Background(), cfg, req)
	if err != nil {
		audit.Error("brocade.export", "Local Brocade evidence-bundle export failed", Err(err))
		fmt.Println(brocadeexport.ErrorJSON(err))
		os.Exit(1)
	}

	// Mirror the local audit record into the structured agent log (no secrets).
	audit.Info("brocade.export", "Local Brocade evidence-bundle export completed",
		F("requester_type", res.Audit.RequesterType),
		F("requester", res.Audit.Requester),
		F("switches", res.Switches),
		F("parsed_files", res.ParsedFiles),
		F("supporting_files", res.SupportingFiles),
		F("warnings", res.Warnings),
		F("output_path", res.Path),
		F("sha256", res.SHA256))

	fmt.Println(res.JSON())
}

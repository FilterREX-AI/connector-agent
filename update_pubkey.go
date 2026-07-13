// ForgeAI Connector Host — Update Signing Public Keys
//
// Contains the Ed25519 public key(s) used to verify signed update manifests.
// Public keys are NOT secret — committing them in source is simpler and more
// reproducible than CI injection.
//
// Key rotation: generate a new keypair, add it here with a new key_id,
// release a new agent version, then sign new manifests with the new private key.
// Old keys remain to verify manifests signed before rotation.

package main

// UpdatePublicKeys maps key_id → base64-encoded Ed25519 public key.
// The agent accepts a manifest signature if it verifies against the key
// matching the manifest's key_id field.
//
// To add a key: generate with `go run scripts/sign-manifest.go keygen`,
// then add the public key here with an appropriate key_id.
var UpdatePublicKeys = map[string]string{
	"primary": "FORGEAI_UPDATE_SIGNING_KEY_PLACEHOLDER",
}

// IsUpdateKeyConfigured returns true if at least one real (non-placeholder)
// public key is present. Used for fail-closed initialization.
func IsUpdateKeyConfigured() bool {
	for _, v := range UpdatePublicKeys {
		if v != "" && v != "FORGEAI_UPDATE_SIGNING_KEY_PLACEHOLDER" {
			return true
		}
	}
	return false
}

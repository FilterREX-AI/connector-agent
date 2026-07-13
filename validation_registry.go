// FilterREX Connector Host — SAN-only target auth registry
//
// SOURCE for the public SAN-only distribution. The export pipeline copies this
// to the public repo as `validation_registry.go` (build-constraint lines
// stripped). Keep it limited to SAN target types.

package main

// targetAuthRegistry maps target types to their auth specifications.
var targetAuthRegistry = map[string]TargetAuthSpec{
	"brocade": {
		TargetType:       "brocade",
		AllowedAuthTypes: []AuthType{AuthTypeUserPassword, AuthTypeAPIToken},
		RequiredCredKeys: []string{},
		DefaultMode:      ProfileModeReadOnly,
		Description:      "Brocade FC switch (FOS REST)",
	},
}

package secrets

import (
	"fmt"
	"strings"
)

// ParseRef splits "name://rest" into provider name and remainder.
func ParseRef(ref string) (string, string, error) {
	idx := strings.Index(ref, "://")
	if idx <= 0 {
		return "", "", fmt.Errorf("secrets: invalid ref %q", ref)
	}
	return ref[:idx], ref[idx+3:], nil
}

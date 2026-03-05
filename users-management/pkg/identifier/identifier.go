// Package identifier provides unique ID generation for user records.
package identifier

import (
	"strings"

	"github.com/google/uuid"
)

// NewId generates a new unique identifier (UUID v4, no dashes, uppercase).
func NewId() string {
	return strings.ToUpper(strings.ReplaceAll(uuid.New().String(), "-", ""))
}

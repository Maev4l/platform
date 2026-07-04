package main

import "strings"

// parseOperators turns the comma-separated SSM value into a set, tolerating
// surrounding spaces and empty entries.
func parseOperators(csv string) map[string]struct{} {
	allow := map[string]struct{}{}
	for _, id := range strings.Split(csv, ",") {
		if id = strings.TrimSpace(id); id != "" {
			allow[id] = struct{}{}
		}
	}
	return allow
}

func isAllowed(allow map[string]struct{}, userID string) bool {
	_, ok := allow[userID]
	return ok
}

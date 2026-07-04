package main

import "encoding/json"

// clickContext is the routing context the notifier embedded in each button's
// value. Short keys mirror the notifier's encoder to fit Slack's 2000-char cap.
type clickContext struct {
	Source     string `json:"s"`
	CallbackID string `json:"c"`
	Payload    string `json:"p,omitempty"`
}

func decodeButtonValue(v string) (clickContext, error) {
	var c clickContext
	err := json.Unmarshal([]byte(v), &c)
	return c, err
}

package models

import "encoding/json"

type AlertMessage struct {
	Target            string          `json:"target"`
	Source            string          `json:"source"`
	SourceDescription string          `json:"sourceDescription"`
	Content           json.RawMessage `json:"content"`
}

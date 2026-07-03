// Package notifications defines the alerting-events SNS message contract shared
// by every producer (publishers to the topic) and the alerter consumer. Keeping
// one struct here prevents the producer/consumer copies from drifting.
package notifications

// Message is the SNS body. The alerter unmarshals it and routes on Target.
// The json tags ARE the wire contract — changing them breaks every consumer.
type Message struct {
	Target            string `json:"target"`            // routing key, e.g. "slack"
	Source            string `json:"source"`            // producer id
	SourceDescription string `json:"sourceDescription"` // human label (Slack context)
	Content           string `json:"content"`           // message body (Markdown by default)
	// Format selects rendering: "" or "markdown" (default) => Markdown;
	// "plain" => literal text. omitempty keeps v1.0.0 producers' bytes unchanged.
	Format string `json:"format,omitempty"`
	// Interactive, when set, renders action buttons under the message. Pointer +
	// omitempty keeps v1.1.0 producers' bytes unchanged.
	Interactive *Interactive `json:"interactive,omitempty"`
}

// Action is one interactive button attached to an alert. The producer owns the
// styling; the alerter passes Style through to Slack unchanged.
type Action struct {
	ID    string `json:"id"`              // action_id, echoed back as the decision's "action"
	Label string `json:"label"`           // button text
	Style string `json:"style,omitempty"` // "", "primary", "danger"
}

// Interactive attaches action buttons to a message. When present, the alerter
// renders a Slack actions block; a click is relayed to the responses topic.
type Interactive struct {
	// CallbackID is the producer's correlation id, opaque to the alerter.
	CallbackID string `json:"callbackId"`
	// Payload is opaque producer context echoed back verbatim. Keep it small:
	// it rides inside the Slack button value, which Slack caps at 2000 chars.
	Payload string   `json:"payload,omitempty"`
	Actions []Action `json:"actions"`
}

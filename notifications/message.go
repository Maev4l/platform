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
}

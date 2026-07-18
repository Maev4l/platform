package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/Maev4l/platform/notifications"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/rs/zerolog/log"
	"github.com/slack-go/slack"
	"isnan.eu/notifier/cmd/mdslack"
)

// SSM parameter name holding the Slack bot token - read from env var (the name
// is not a secret; the value is fetched from SSM at startup).
var slackTokenParam string = os.Getenv("SLACK_TOKEN")

var channelId string = os.Getenv("SLACK_CHANNEL_ID")

// slackClient is initialised once in main() after the token is fetched.
var slackClient *slack.Client

func getSlackTokenFromSSM() string {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to load AWS SDK config")
	}
	ssmClient := ssm.NewFromConfig(cfg)
	withDecryption := true
	input := &ssm.GetParameterInput{Name: &slackTokenParam, WithDecryption: &withDecryption}
	result, err := ssmClient.GetParameter(context.Background(), input)
	if err != nil {
		log.Fatal().Err(err).Str("parameter", slackTokenParam).Msg("Failed to get Slack token from SSM")
	}
	return *result.Parameter.Value
}

// buildMessageBlocks assembles the Slack Block Kit payload: a context block for
// the source label (when present) followed by the rendered body.
func buildMessageBlocks(alert *notifications.Message) []slack.Block {
	var blocks []slack.Block
	if alert.SourceDescription != "" {
		blocks = append(blocks, slack.NewContextBlock("",
			slack.NewTextBlockObject(slack.MarkdownType, alert.SourceDescription, false, false)))
	}
	blocks = append(blocks, bodyBlocks(alert)...)
	if alert.Interactive != nil && len(alert.Interactive.Actions) > 0 {
		blocks = append(blocks, buildActionBlock(alert))
	}
	return blocks
}

// buttonContext is the routing context embedded in each button's value. It is
// short-keyed to stay well under Slack's 2000-char value cap. The responder
// decodes the identical shape.
type buttonContext struct {
	Source     string `json:"s"`
	CallbackID string `json:"c"`
	Payload    string `json:"p,omitempty"`
}

func encodeButtonValue(source, callbackID, payload string) string {
	b, _ := json.Marshal(buttonContext{Source: source, CallbackID: callbackID, Payload: payload})
	return string(b)
}

// buildActionBlock renders the producer's buttons. The action_id carries the
// decision; the value carries routing context the responder echoes back.
func buildActionBlock(alert *notifications.Message) slack.Block {
	value := encodeButtonValue(alert.Source, alert.Interactive.CallbackID, alert.Interactive.Payload)
	if len(value) > 2000 {
		// Slack rejects values > 2000 chars; log so an oversized payload is visible.
		log.Warn().Int("len", len(value)).Str("source", alert.Source).
			Msg("Button value exceeds Slack 2000-char limit; click routing may fail")
	}
	elements := make([]slack.BlockElement, 0, len(alert.Interactive.Actions))
	for _, a := range alert.Interactive.Actions {
		btn := slack.NewButtonBlockElement(a.ID, value,
			slack.NewTextBlockObject(slack.PlainTextType, a.Label, false, false))
		if a.Style != "" {
			btn.Style = slack.Style(a.Style)
		}
		elements = append(elements, btn)
	}
	// block_id is the callbackId so the acted-on message is self-identifying in logs.
	return slack.NewActionBlock(alert.Interactive.CallbackID, elements...)
}

// bodyBlocks renders the content. "plain" sends literal text; otherwise Markdown,
// falling back to literal sections so an alert is never dropped.
func bodyBlocks(alert *notifications.Message) []slack.Block {
	if alert.Format == "plain" {
		return mdslack.PlainSections(alert.Content)
	}
	blocks, err := mdslack.Render(alert.Content)
	if err != nil {
		log.Warn().Err(err).Msg("Markdown render error, falling back to plain text")
		return mdslack.PlainSections(alert.Content)
	}
	if len(blocks) == 0 {
		log.Warn().Msg("Markdown render produced no blocks, falling back to plain text")
		return mdslack.PlainSections(alert.Content)
	}
	return blocks
}

// sendAlert posts the alert to the configured Slack channel. Slack is the only
// channel, so there is no target registry — the call is direct.
func sendAlert(alert *notifications.Message) error {
	if alert.Content == "" {
		return nil
	}
	blocks := buildMessageBlocks(alert)
	// Disable unfurling: alert bodies routinely carry bare hostnames (e.g. a cert's
	// common name) which Slack otherwise fetches and expands into a full link/media
	// preview card, drowning the actual alert. These are ops notifications, never
	// link shares — no unfurl is ever wanted.
	_, _, err := slackClient.PostMessage(channelId,
		slack.MsgOptionBlocks(blocks...),
		slack.MsgOptionDisableLinkUnfurl(),
		slack.MsgOptionDisableMediaUnfurl(),
	)
	if err != nil {
		log.Error().Err(err).Msg("Failed to send alert")
		return err
	}
	return nil
}

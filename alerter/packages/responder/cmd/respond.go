package main

import (
	"fmt"
	"net/url"

	"github.com/slack-go/slack"
)

// validResponseURL confirms an interaction response_url points at Slack's webhook
// host before we POST to it. The URL arrives inside the signature-verified payload,
// so this is defense-in-depth: it stops a forged or unexpected response_url from
// becoming an outbound SSRF if the signing secret is ever compromised.
func validResponseURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host == "hooks.slack.com"
}

// confirmationMessage replaces the original alert: it keeps the original blocks
// but strips the actions block (so buttons can't be re-clicked) and appends a
// context line naming who acted. This is the Level-1 stateless double-click guard.
// userID is a Slack user ID (e.g. "U123"); it is formatted as a <@ID> mention,
// which only resolves to a clickable name when given an ID, not a display name.
func confirmationMessage(original slack.Blocks, actionLabel, userID string) *slack.WebhookMessage {
	kept := make([]slack.Block, 0, len(original.BlockSet)+1)
	for _, b := range original.BlockSet {
		if b.BlockType() == slack.MBTAction {
			continue // drop buttons
		}
		kept = append(kept, b)
	}
	kept = append(kept, slack.NewContextBlock("",
		slack.NewTextBlockObject(slack.MarkdownType,
			fmt.Sprintf(":white_check_mark: *%s* by <@%s>", actionLabel, userID), false, false)))

	return &slack.WebhookMessage{
		ReplaceOriginal: true,
		Blocks:          &slack.Blocks{BlockSet: kept},
	}
}

// rejectionMessage is a private notice to an unauthorised clicker. It does not
// touch the shared message, so the buttons remain for an authorised operator.
func rejectionMessage(text string) *slack.WebhookMessage {
	return &slack.WebhookMessage{
		ResponseType:    "ephemeral",
		ReplaceOriginal: false,
		Text:            text,
	}
}

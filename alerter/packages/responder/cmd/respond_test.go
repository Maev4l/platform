package main

import (
	"testing"

	"github.com/slack-go/slack"
)

func TestConfirmationMessage_DropsActionsAddsContext(t *testing.T) {
	original := slack.Blocks{BlockSet: []slack.Block{
		slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, "Approve deploy?", false, false), nil, nil),
		slack.NewActionBlock("req-1", slack.NewButtonBlockElement("approve", "{}",
			slack.NewTextBlockObject(slack.PlainTextType, "OK", false, false))),
	}}
	msg := confirmationMessage(original, "OK", "jsue")

	if !msg.ReplaceOriginal {
		t.Fatal("confirmation must replace the original message")
	}
	for _, b := range msg.Blocks.BlockSet {
		if b.BlockType() == slack.MBTAction {
			t.Fatal("actions block must be removed so buttons can't be re-clicked")
		}
	}
	// Original content is preserved (still one section) + a confirmation context line.
	var sections, contexts int
	for _, b := range msg.Blocks.BlockSet {
		switch b.BlockType() {
		case slack.MBTSection:
			sections++
		case slack.MBTContext:
			contexts++
		}
	}
	if sections != 1 || contexts != 1 {
		t.Fatalf("expected 1 section + 1 context, got %d/%d", sections, contexts)
	}
}

func TestValidResponseURL(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want bool
	}{
		{"slack https", "https://hooks.slack.com/actions/T1/2/abc", true},
		{"wrong host", "https://evil.example.com/x", false},
		{"http scheme", "http://hooks.slack.com/actions/T1/2/abc", false},
		{"host suffix trick", "https://hooks.slack.com.evil.com/x", false},
		{"empty", "", false},
		{"garbage", "::not a url", false},
	}
	for _, c := range cases {
		if got := validResponseURL(c.url); got != c.want {
			t.Errorf("%s: validResponseURL(%q) = %v, want %v", c.name, c.url, got, c.want)
		}
	}
}

func TestRejectionMessage_IsEphemeral(t *testing.T) {
	msg := rejectionMessage("nope")
	if msg.ResponseType != "ephemeral" {
		t.Fatalf("expected ephemeral, got %q", msg.ResponseType)
	}
	if msg.ReplaceOriginal {
		t.Fatal("rejection must NOT replace the original (buttons stay for authorised users)")
	}
}

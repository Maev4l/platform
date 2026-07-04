package main

import (
	"context"
	"encoding/json"

	"github.com/Maev4l/platform/notifications"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/slack-go/slack"
)

func handler(ctx context.Context, snsEvent events.SNSEvent) {
	for _, record := range snsEvent.Records {
		message := &notifications.Message{}
		if err := json.Unmarshal([]byte(record.SNS.Message), message); err != nil {
			log.Error().Err(err).Msg("Failed to unmarshall SNS event message")
			return
		}
		// Slack is the only channel. Keep the field for producer compatibility;
		// warn (do not drop) on anything else so a misrouted producer is visible.
		if message.Target != "" && message.Target != "slack" {
			log.Warn().Str("target", message.Target).Msg("Unknown target; sending to Slack anyway")
		}
		if err := sendAlert(message); err != nil {
			log.Error().Err(err).Str("source", message.Source).Msg("Failed to send message")
			return
		}
		log.Debug().Str("source", message.Source).Msg("Message sent")
	}
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	slackClient = slack.New(getSlackTokenFromSSM())
	lambda.Start(handler)
}

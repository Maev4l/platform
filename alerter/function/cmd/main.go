package main

import (
	"context"
	"encoding/json"

	"github.com/Maev4l/platform/notifications"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"isnan.eu/alerting/cmd/targets"
)

var TARGETS = map[string]targets.Target{}

func handler(ctx context.Context, snsEvent events.SNSEvent) {
	for _, record := range snsEvent.Records {
		snsRecord := record.SNS

		message := &notifications.Message{}

		err := json.Unmarshal([]byte(snsRecord.Message), message)
		if err != nil {
			log.Error().Err(err).Msg("Failed to unmarshall SNS event message")
			return
		}
		target, ok := TARGETS[message.Target]
		if ok {
			err = target.SendAlert(message)
			if err != nil {
				log.Error().Err(err).Str("target", message.Target).Msg("Failed to send message")
				return
			}
			log.Debug().Str("source", message.Source).Str("target", message.Target).Msg("Message sent")
		} else {
			log.Warn().Str("target", message.Target).Msg("Target is not registered")
			return
		}
	}
}

func registerTargets() {
	slackTarget := targets.NewSlackTarget()
	TARGETS[slackTarget.GetName()] = slackTarget
}

func main() {
	// Match the platform-wide zerolog convention (see cost-report): compact
	// unix timestamps; the default global logger already emits to stderr with a
	// timestamp field, both of which CloudWatch captures.
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	registerTargets()
	lambda.Start(handler)
}

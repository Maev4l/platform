package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	log "github.com/sirupsen/logrus"
	"isnan.eu/alerting/cmd/models"
	"isnan.eu/alerting/cmd/targets"
)

var TARGETS = map[string]targets.Target{}

func handler(ctx context.Context, snsEvent events.SNSEvent) {
	for _, record := range snsEvent.Records {
		snsRecord := record.SNS

		message := &models.AlertMessage{}

		err := json.Unmarshal([]byte(snsRecord.Message), message)
		if err != nil {
			log.Errorf("Failed to unmarshall SNS event message: %v", err.Error())
			return
		}
		target, ok := TARGETS[message.Target]
		if ok {
			err = target.SendAlert(message)
			if err != nil {
				log.Errorf("Failed to send message to %s", message.Target)
				return
			}
			log.Debugf("Message from %s sent to %s", message.Source, message.Target)
		} else {
			log.Warnf("Target %s is not registered", message.Target)
			return
		}
	}
}

func registerTargets() {
	slackTarget := targets.NewSlackTarget()
	TARGETS[slackTarget.GetName()] = slackTarget
}

func main() {
	log.SetOutput(os.Stdout)
	registerTargets()
	lambda.Start(handler)
}

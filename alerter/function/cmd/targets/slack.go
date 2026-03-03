package targets

import (
	"context"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"isnan.eu/alerting/cmd/models"
)

// SSM parameter name containing the Slack token - read from env var
var slackTokenParam string = os.Getenv("SLACK_TOKEN")

var channelId string = os.Getenv("SLACK_CHANNEL_ID")

// getSlackTokenFromSSM fetches the Slack token from AWS SSM Parameter Store
func getSlackTokenFromSSM() string {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("Unable to load AWS SDK config: %v", err)
	}

	ssmClient := ssm.NewFromConfig(cfg)
	withDecryption := true
	input := &ssm.GetParameterInput{
		Name:           &slackTokenParam,
		WithDecryption: &withDecryption,
	}

	result, err := ssmClient.GetParameter(context.Background(), input)
	if err != nil {
		log.Fatalf("Failed to get Slack token from SSM parameter %s: %v", slackTokenParam, err)
	}

	return *result.Parameter.Value
}

type (
	slackNotifier struct {
		name        string
		slackClient *slack.Client
	}
)

func (n slackNotifier) GetName() string {
	return n.name
}

func (n slackNotifier) SendAlert(alert *models.AlertMessage) error {
	content := string(alert.Content)
	if content != "" {

		attachment := slack.Attachment{
			Pretext: alert.SourceDescription,
			Text:    content,
			/*
				// Color Styles the Text, making it possible to have like Warnings etc.
				Color: "#36a64f",
				// Fields are Optional extra data!
				Fields: []slack.AttachmentField{
					{
						Title: "Date",
						Value: time.Now().String(),
					},
				},
			*/
		}

		_, _, err := n.slackClient.PostMessage(channelId, slack.MsgOptionAttachments(attachment))

		if err != nil {
			log.Errorf("Failed to send alert to %s", n.name)
			return err
		}

	}
	return nil
}

func NewSlackTarget() Target {
	// Fetch token from SSM at initialization time
	token := getSlackTokenFromSSM()
	target := slackNotifier{
		name:        "slack",
		slackClient: slack.New(token),
	}
	return target
}

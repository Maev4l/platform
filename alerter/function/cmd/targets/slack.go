package targets

import (
	"context"
	"os"

	"github.com/Maev4l/platform/notifications"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"isnan.eu/alerting/cmd/targets/mdslack"
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

// buildMessageBlocks assembles the Slack Block Kit payload: a context block for
// the source label (when present) followed by the rendered body.
func buildMessageBlocks(alert *notifications.Message) []slack.Block {
	var blocks []slack.Block
	if alert.SourceDescription != "" {
		blocks = append(blocks, slack.NewContextBlock("",
			slack.NewTextBlockObject(slack.MarkdownType, alert.SourceDescription, false, false)))
	}
	return append(blocks, bodyBlocks(alert)...)
}

// bodyBlocks renders the content. "plain" sends literal text; otherwise Markdown,
// falling back to a literal section so an alert is never dropped.
func bodyBlocks(alert *notifications.Message) []slack.Block {
	if alert.Format == "plain" {
		return []slack.Block{plainSection(alert.Content)}
	}
	blocks, err := mdslack.Render(alert.Content)
	if err != nil || len(blocks) == 0 {
		log.Warnf("Markdown render failed, falling back to plain text: %v", err)
		return []slack.Block{plainSection(alert.Content)}
	}
	return blocks
}

// plainSection wraps a string in a plain_text section block.
func plainSection(s string) slack.Block {
	return slack.NewSectionBlock(slack.NewTextBlockObject(slack.PlainTextType, s, false, false), nil, nil)
}

func (n slackNotifier) SendAlert(alert *notifications.Message) error {
	if alert.Content == "" {
		return nil
	}
	blocks := buildMessageBlocks(alert)
	_, _, err := n.slackClient.PostMessage(channelId, slack.MsgOptionBlocks(blocks...))
	if err != nil {
		log.Errorf("Failed to send alert to %s", n.name)
		return err
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

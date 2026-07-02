package targets

import (
	"context"
	"os"

	"github.com/Maev4l/platform/notifications"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/rs/zerolog/log"
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
		log.Fatal().Err(err).Msg("Unable to load AWS SDK config")
	}

	ssmClient := ssm.NewFromConfig(cfg)
	withDecryption := true
	input := &ssm.GetParameterInput{
		Name:           &slackTokenParam,
		WithDecryption: &withDecryption,
	}

	result, err := ssmClient.GetParameter(context.Background(), input)
	if err != nil {
		log.Fatal().Err(err).Str("parameter", slackTokenParam).Msg("Failed to get Slack token from SSM")
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
// falling back to literal sections so an alert is never dropped. Plain content is
// split on Slack's 3000-char section limit (via mdslack.PlainSections) so large
// plain/fallback payloads are not rejected by the API.
func bodyBlocks(alert *notifications.Message) []slack.Block {
	if alert.Format == "plain" {
		return mdslack.PlainSections(alert.Content)
	}
	blocks, err := mdslack.Render(alert.Content)
	// Distinguish the two fallback triggers so operators aren't shown a
	// "<nil>" error when the cause is simply empty/unrenderable content.
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

func (n slackNotifier) SendAlert(alert *notifications.Message) error {
	if alert.Content == "" {
		return nil
	}
	blocks := buildMessageBlocks(alert)
	_, _, err := n.slackClient.PostMessage(channelId, slack.MsgOptionBlocks(blocks...))
	if err != nil {
		log.Error().Err(err).Str("target", n.name).Msg("Failed to send alert")
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

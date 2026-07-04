package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/slack-go/slack"
)

// Env vars hold SSM parameter NAMES (not values — the value is fetched from SSM
// at cold start) and the non-secret topic ARN.
var (
	signingSecretParam = os.Getenv("SLACK_SIGNING_SECRET") // SSM name
	operatorsParam     = os.Getenv("SLACK_OPERATORS")      // SSM name
	responsesTopicArn  = os.Getenv("RESPONSES_TOPIC_ARN")

	signingSecret string
	operators     map[string]struct{}
	snsClient     *sns.Client
)

// responsePayload is the SNS body producers consume.
type responsePayload struct {
	Source     string    `json:"source"`
	CallbackID string    `json:"callbackId"`
	Action     string    `json:"action"`
	Payload    string    `json:"payload,omitempty"`
	User       slackUser `json:"user"`
	Channel    string    `json:"channel"`
	Ts         string    `json:"ts"`
}

type slackUser struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func buildResponsePayload(c clickContext, action, userID, userName, channel, ts string) ([]byte, error) {
	return json.Marshal(responsePayload{
		Source: c.Source, CallbackID: c.CallbackID, Action: action, Payload: c.Payload,
		User: slackUser{ID: userID, Name: userName}, Channel: channel, Ts: ts,
	})
}

func getSSMParam(ssmClient *ssm.Client, name string) string {
	withDecryption := true
	out, err := ssmClient.GetParameter(context.Background(), &ssm.GetParameterInput{
		Name: &name, WithDecryption: &withDecryption,
	})
	if err != nil {
		log.Fatal().Err(err).Str("parameter", name).Msg("Failed to get SSM parameter")
	}
	return *out.Parameter.Value
}

// postToSlack posts to the interaction response_url, but only after confirming it
// targets Slack's webhook host. The error deliberately omits the URL (it carries a
// secret token). Defense-in-depth against a forged response_url becoming an SSRF.
func postToSlack(ctx context.Context, responseURL string, msg *slack.WebhookMessage) error {
	if !validResponseURL(responseURL) {
		return errors.New("response_url is not an https hooks.slack.com URL")
	}
	return slack.PostWebhookContext(ctx, responseURL, msg)
}

// ack returns 200 so Slack never retries; the button was already consumed on
// the first successful click, so re-delivery would only double-publish.
func ack() (events.LambdaFunctionURLResponse, error) {
	return events.LambdaFunctionURLResponse{StatusCode: 200}, nil
}

func handler(ctx context.Context, req events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
	body := []byte(req.Body)
	if req.IsBase64Encoded {
		decoded, err := base64.StdEncoding.DecodeString(req.Body)
		if err != nil {
			log.Error().Err(err).Msg("Failed to decode base64 body")
			return events.LambdaFunctionURLResponse{StatusCode: 400}, nil
		}
		body = decoded
	}

	// Gate 1: the request must be genuinely from Slack and fresh. The verifier's
	// error can embed the attacker's computed signature, so it is logged
	// server-side only and never echoed back in the HTTP response.
	if err := verifySignature(req.Headers, body, signingSecret); err != nil {
		log.Warn().Err(err).Msg("Slack signature verification failed")
		return events.LambdaFunctionURLResponse{StatusCode: 401}, nil
	}

	// Slack sends application/x-www-form-urlencoded with payload=<json>.
	form, err := url.ParseQuery(string(body))
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse form body")
		return events.LambdaFunctionURLResponse{StatusCode: 400}, nil
	}
	var cb slack.InteractionCallback
	if err := json.Unmarshal([]byte(form.Get("payload")), &cb); err != nil {
		log.Error().Err(err).Msg("Failed to parse interaction payload")
		return events.LambdaFunctionURLResponse{StatusCode: 400}, nil
	}

	actions := cb.ActionCallback.BlockActions
	if len(actions) == 0 {
		log.Warn().Msg("Interaction has no block actions; ignoring")
		return ack()
	}
	ba := actions[0]

	clickCtx, err := decodeButtonValue(ba.Value)
	if err != nil {
		log.Error().Err(err).Msg("Failed to decode button value; ignoring")
		return ack()
	}

	// Gate 2: only allow-listed operators fire the action.
	if !isAllowed(operators, cb.User.ID) {
		log.Warn().Str("user", cb.User.ID).Str("callbackId", clickCtx.CallbackID).Msg("Unauthorised click")
		if err := postToSlack(ctx, cb.ResponseURL,
			rejectionMessage(":x: You're not authorized to act on this alert.")); err != nil {
			log.Error().Err(err).Msg("Failed to post rejection")
		}
		return ack()
	}

	// Relay the decision to producers.
	payload, err := buildResponsePayload(clickCtx, ba.ActionID, cb.User.ID, cb.User.Name, cb.Channel.ID, cb.Message.Timestamp)
	if err != nil {
		log.Error().Err(err).Msg("Failed to build response payload")
		return ack()
	}
	if _, err := snsClient.Publish(ctx, &sns.PublishInput{
		TopicArn: &responsesTopicArn,
		Message:  aws.String(string(payload)),
		// source attribute lets producers filter-policy their subscription.
		MessageAttributes: map[string]snstypes.MessageAttributeValue{
			"source": {DataType: aws.String("String"), StringValue: aws.String(clickCtx.Source)},
		},
	}); err != nil {
		// Log and still ack: retries risk double-publishing.
		log.Error().Err(err).Str("callbackId", clickCtx.CallbackID).Msg("Failed to publish response")
		return ack()
	}

	// Consume the buttons + confirm who acted. Mention must be the user ID
	// (not display name) for Slack to render it as a resolving <@...> mention.
	if err := postToSlack(ctx, cb.ResponseURL,
		confirmationMessage(cb.Message.Blocks, ba.Text.Text, cb.User.ID)); err != nil {
		log.Error().Err(err).Msg("Failed to update original message")
	}

	log.Info().Str("action", ba.ActionID).Str("callbackId", clickCtx.CallbackID).
		Str("user", cb.User.ID).Msg("Decision relayed")
	return ack()
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatal().Err(err).Msg("Unable to load AWS SDK config")
	}
	ssmClient := ssm.NewFromConfig(cfg)
	signingSecret = getSSMParam(ssmClient, signingSecretParam)
	operators = parseOperators(getSSMParam(ssmClient, operatorsParam))
	snsClient = sns.NewFromConfig(cfg)

	lambda.Start(handler)
}

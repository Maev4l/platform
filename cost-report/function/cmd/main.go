package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Maev4l/platform/notifications"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	source   = "cost-report"
	ceRegion = "us-east-1" // Cost Explorer is a global service reached via us-east-1
	// Markdown to match the alerter's default rendering (same as the report path).
	// The service name is fenced as inline code so it reads as a literal, not prose.
	failureText = "# 💸 AWS Cost Report — Failed\n\nFailed to generate the report — check the CloudWatch logs for `cost-report`."
)

// snsPublisher is the subset of the SNS client we use (small interface keeps
// the publish path swappable/testable).
type snsPublisher interface {
	Publish(ctx context.Context, in *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error)
}

// publish marshals a notifications.Message and sends it to the topic.
func publish(ctx context.Context, client snsPublisher, topicArn, content, format string) error {
	body, err := json.Marshal(notifications.Message{
		Target:            "slack",
		Source:            source,
		SourceDescription: "",
		Content:           content,
		Format:            format,
	})
	if err != nil {
		return err
	}
	_, err = client.Publish(ctx, &sns.PublishInput{
		TopicArn: aws.String(topicArn),
		Message:  aws.String(string(body)),
	})
	return err
}

func handler(ctx context.Context) error {
	topicArn := os.Getenv("SNS_TOPIC_ARN")
	if topicArn == "" {
		return fmt.Errorf("SNS_TOPIC_ARN is not set")
	}

	// Default config (eu-central-1) for SNS.
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}
	snsClient := sns.NewFromConfig(cfg)

	// CE client pinned to us-east-1.
	ceClient := costexplorer.NewFromConfig(cfg, func(o *costexplorer.Options) {
		o.Region = ceRegion
	})

	report, err := fetchReport(ctx, ceClient, time.Now())
	if err != nil {
		log.Error().Err(err).Msg("failed to fetch cost report")
		// Surface the failure in Slack rather than failing silently.
		if perr := publish(ctx, snsClient, topicArn, failureText, "markdown"); perr != nil {
			log.Error().Err(perr).Msg("failed to publish failure alert")
		}
		return err
	}

	if err := publish(ctx, snsClient, topicArn, BuildMarkdown(report), "markdown"); err != nil {
		log.Error().Err(err).Msg("failed to publish cost report")
		return err
	}

	log.Info().Str("month", report.MonthLabel).Msg("cost report published")
	return nil
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	lambda.Start(handler)
}

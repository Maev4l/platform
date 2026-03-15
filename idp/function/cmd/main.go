// Platform IDP Lambda - handles Cognito triggers with per-app approval workflow.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Maev4l/platform/users-management/pkg/cognito"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/rs/zerolog/log"
)

// loadAppClientConfig reads app client mappings from SSM and builds AppClientConfig.
// SSM stores JSON: {"appName": "clientId", ...}
// Returns map: clientId -> AppConfig
func loadAppClientConfig(ssmClient *ssm.Client) map[string]cognito.AppConfig {
	paramName := "platform.idp.app-clients"
	result, err := ssmClient.GetParameter(context.TODO(), &ssm.GetParameterInput{
		Name: &paramName,
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to load app-clients from SSM")
		return make(map[string]cognito.AppConfig)
	}

	// Parse JSON: appName -> clientId
	var appToClient map[string]string
	if err := json.Unmarshal([]byte(*result.Parameter.Value), &appToClient); err != nil {
		log.Error().Err(err).Msg("Failed to parse app-clients JSON")
		return make(map[string]cognito.AppConfig)
	}

	// Invert to clientId -> AppConfig
	clientConfig := make(map[string]cognito.AppConfig)
	for appName, clientID := range appToClient {
		clientConfig[clientID] = cognito.AppConfig{
			AppName:       appName,
			ApprovedGroup: appName, // Group name matches app name by convention
		}
		log.Info().Str("app", appName).Str("clientId", clientID).Msg("Loaded app client config")
	}

	return clientConfig
}

func main() {
	handler := cognito.NewHandler()

	// Initialize SSM client and load app client config
	cfg, _ := config.LoadDefaultConfig(context.TODO(), config.WithRegion(os.Getenv("REGION")))
	ssmClient := ssm.NewFromConfig(cfg)
	handler.AppClientConfig = loadAppClientConfig(ssmClient)

	// Notification for new user signups
	// Includes AWS CLI command for admin to approve user
	handler.GetNotification = func(ctx context.Context, event *cognito.PreSignUpEvent, appConfig *cognito.AppConfig) (*cognito.NotificationPayload, bool) {
		appName := "unknown app"
		groupName := "unknown"
		if appConfig != nil {
			appName = appConfig.AppName
			groupName = appConfig.ApprovedGroup
		}
		awsCliCmd := fmt.Sprintf(
			"aws cognito-idp admin-add-user-to-group --user-pool-id %s --username %s --group-name %s",
			event.UserPoolID,
			event.UserName,
			groupName,
		)
		content := fmt.Sprintf(
			"User %s requesting access to %s - Approve with: %s",
			event.Email,
			appName,
			awsCliCmd,
		)
		return &cognito.NotificationPayload{
			Source:            "platform-idp-onboard-users",
			SourceDescription: fmt.Sprintf("%s user sign up", appName),
			Target:            "slack",
			Content:           content,
		}, true
	}

	// Notification when unapproved user tries to access an app
	// Includes AWS CLI command for admin to approve user
	handler.ShouldNotifyForApp = func(ctx context.Context, event *cognito.PostAuthenticationEvent, appConfig *cognito.AppConfig) (*cognito.NotificationPayload, bool) {
		awsCliCmd := fmt.Sprintf(
			"aws cognito-idp admin-add-user-to-group --user-pool-id %s --username %s --group-name %s",
			event.UserPoolID,
			event.UserName,
			appConfig.ApprovedGroup,
		)
		content := fmt.Sprintf(
			"User %s requesting access to %s - Approve with: %s",
			event.Email,
			appConfig.AppName,
			awsCliCmd,
		)
		return &cognito.NotificationPayload{
			Source:            "platform-idp-app-approval",
			SourceDescription: fmt.Sprintf("%s access request", appConfig.AppName),
			Target:            "slack",
			Content:           content,
		}, true
	}

	lambda.Start(handler.Handle)
}

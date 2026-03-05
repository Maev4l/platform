// Default Cognito Lambda for Alexandria platform.
// Uses base handler with Alexandria-specific notification.
package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/Maev4l/platform/users-management/pkg/cognito"
)

func main() {
	handler := cognito.NewHandler()

	// Configure Alexandria-specific notification
	handler.GetNotification = func(ctx context.Context, event *cognito.PreSignUpEvent) (*cognito.NotificationPayload, bool) {
		return &cognito.NotificationPayload{
			Source:            "alexandria-onboard-users",
			SourceDescription: "Alexandria user sign up (pre)",
			Target:            "slack",
			Content:           fmt.Sprintf("Awaiting registration for %s", event.Email),
		}, true
	}

	lambda.Start(handler.Handle)
}

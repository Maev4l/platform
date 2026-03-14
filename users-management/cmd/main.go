// Default Cognito Lambda for Alexandria platform.
// Uses base handler with Alexandria-specific notification.
package main

import (
	"github.com/Maev4l/platform/users-management/pkg/cognito"
	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	handler := cognito.NewHandler()

	lambda.Start(handler.Handle)
}

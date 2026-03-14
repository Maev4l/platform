package cognito

import (
	"context"
	"net/mail"
)

// =============================================================================
// HOOK FUNCTION TYPES
// Derived Lambdas override these to customize behavior
// =============================================================================

// ValidateSignUpFunc validates a native signup request.
// Return error to reject the signup.
type ValidateSignUpFunc func(ctx context.Context, event *PreSignUpEvent) error

// GetCustomAttributesFunc returns additional attributes to set post-confirmation.
// Base attributes (Id, Approved, email) are always set; these are appended.
type GetCustomAttributesFunc func(ctx context.Context, event *PostConfirmationEvent) ([]Attribute, error)

// OnUserConfirmedFunc runs after attributes are applied.
// Use for side effects: create DB record, send welcome email, etc.
type OnUserConfirmedFunc func(ctx context.Context, event *PostConfirmationEvent) error

// GetNotificationFunc returns whether to send a notification and the payload.
// Return (nil, false) to skip notification.
// Return (payload, true) to send.
type GetNotificationFunc func(ctx context.Context, event *PreSignUpEvent) (*NotificationPayload, bool)

// =============================================================================
// DEFAULT IMPLEMENTATIONS
// =============================================================================

// DefaultValidateSignUp accepts all signups with valid email format
func DefaultValidateSignUp(ctx context.Context, event *PreSignUpEvent) error {
	return validateEmailFormat(event.Email)
}

// DefaultGetCustomAttributes returns no extra attributes
func DefaultGetCustomAttributes(ctx context.Context, event *PostConfirmationEvent) ([]Attribute, error) {
	return nil, nil
}

// DefaultOnUserConfirmed does nothing
func DefaultOnUserConfirmed(ctx context.Context, event *PostConfirmationEvent) error {
	return nil
}

// DefaultGetNotification returns no notification
func DefaultGetNotification(ctx context.Context, event *PreSignUpEvent) (*NotificationPayload, bool) {
	return nil, false
}

// =============================================================================
// APP APPROVAL HOOKS
// For per-app approval workflow (PostAuthentication + PreTokenGeneration)
// =============================================================================

// ShouldNotifyForAppFunc returns notification payload for unapproved app access.
// Return (nil, false) to skip notification.
// Return (payload, true) to send notification to admin.
type ShouldNotifyForAppFunc func(ctx context.Context, event *PostAuthenticationEvent, appConfig *AppConfig) (*NotificationPayload, bool)

// OnTokenDeniedFunc is called when token issuance is blocked for unapproved user.
// Use for logging, metrics, or side effects.
type OnTokenDeniedFunc func(ctx context.Context, event *PreTokenGenerationEvent, appConfig *AppConfig) error

// DefaultShouldNotifyForApp returns no notification
func DefaultShouldNotifyForApp(ctx context.Context, event *PostAuthenticationEvent, appConfig *AppConfig) (*NotificationPayload, bool) {
	return nil, false
}

// DefaultOnTokenDenied does nothing
func DefaultOnTokenDenied(ctx context.Context, event *PreTokenGenerationEvent, appConfig *AppConfig) error {
	return nil
}

// validateEmailFormat checks if email has valid format
func validateEmailFormat(email string) error {
	_, err := mail.ParseAddress(email)
	return err
}

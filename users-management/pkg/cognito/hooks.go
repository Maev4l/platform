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

// validateEmailFormat checks if email has valid format
func validateEmailFormat(email string) error {
	_, err := mail.ParseAddress(email)
	return err
}

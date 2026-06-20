// Package cognito provides an extensible handler for AWS Cognito Lambda triggers.
// Derived Lambdas customize behavior by overriding hook functions.
package cognito

import "github.com/Maev4l/platform/notifications"

// Attribute represents a Cognito user attribute to set
type Attribute struct {
	Name  string
	Value string
}

// PreSignUpEvent contains parsed Cognito PreSignUp trigger data
type PreSignUpEvent struct {
	UserPoolID     string
	UserName       string
	Email          string
	TriggerSource  string // PreSignUp_SignUp | PreSignUp_ExternalProvider
	CallerContext  CallerContext
	UserAttributes map[string]string
	// Raw event for passthrough to response
	RawEvent map[string]interface{}
}

// PostConfirmationEvent contains parsed Cognito PostConfirmation trigger data
type PostConfirmationEvent struct {
	UserPoolID     string
	UserName       string
	Email          string
	TriggerSource  string
	UserAttributes map[string]string
	// Raw event for passthrough to response
	RawEvent map[string]interface{}
}

// ExistingUser contains info about an existing user (for duplicate checking)
type ExistingUser struct {
	UserName  string
	Email     string
	IsNative  bool     // true if username == email (native signup)
	Providers []string // Google, Facebook, native, etc.
}

// NotificationPayload is retained as a backward-compatible alias. The canonical
// type now lives in the shared notifications module so producers and the alerter
// consumer share one wire contract. Existing hooks returning *NotificationPayload
// keep compiling unchanged.
type NotificationPayload = notifications.Message

// Identity represents a federated identity from Cognito
type Identity struct {
	ProviderName string `json:"providerName"`
	ProviderType string `json:"providerType"`
	UserId       string `json:"userId"`
}

// CallerContext contains app client info from Cognito trigger events
type CallerContext struct {
	ClientId string
}

// PostAuthenticationEvent for PostAuthentication_Authentication trigger
type PostAuthenticationEvent struct {
	UserPoolID     string
	UserName       string
	Email          string
	TriggerSource  string
	CallerContext  CallerContext
	UserAttributes map[string]string
	RawEvent       map[string]interface{}
}

// PreTokenGenerationEvent for TokenGeneration_* triggers
type PreTokenGenerationEvent struct {
	UserPoolID     string
	UserName       string
	TriggerSource  string
	CallerContext  CallerContext
	UserAttributes map[string]string
	GroupConfig    GroupConfiguration
	RawEvent       map[string]interface{}
}

// GroupConfiguration contains group override info from PreTokenGeneration
type GroupConfiguration struct {
	GroupsToOverride []string
}

// AppConfig maps clientId to app metadata for per-app approval workflow
type AppConfig struct {
	AppName       string
	ApprovedGroup string
}

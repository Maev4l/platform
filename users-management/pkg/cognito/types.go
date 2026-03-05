// Package cognito provides an extensible handler for AWS Cognito Lambda triggers.
// Derived Lambdas customize behavior by overriding hook functions.
package cognito

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

// NotificationPayload defines the structure for signup notifications
type NotificationPayload struct {
	Source            string `json:"source"`
	SourceDescription string `json:"sourceDescription"`
	Target            string `json:"target"`
	Content           string `json:"content"`
}

// Identity represents a federated identity from Cognito
type Identity struct {
	ProviderName string `json:"providerName"`
	ProviderType string `json:"providerType"`
	UserId       string `json:"userId"`
}

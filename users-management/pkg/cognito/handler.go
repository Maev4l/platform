package cognito

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Maev4l/platform/users-management/pkg/identifier"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/rs/zerolog/log"
)

// Handler processes Cognito Lambda triggers with customizable hooks.
// Use NewHandler() to create with defaults, then override hooks as needed.
type Handler struct {
	cognitoClient *cognitoidentityprovider.Client
	snsClient     *sns.Client
	snsTopicArn   string

	// =========================================================================
	// CONFIGURABLE HOOKS
	// Override these in derived Lambdas to customize behavior
	// =========================================================================

	// ValidateSignUp validates native signup requests.
	// Default: accepts valid email format.
	// Override to: add domain restrictions, block disposable emails, etc.
	ValidateSignUp ValidateSignUpFunc

	// GetCustomAttributes returns extra attributes for post-confirmation.
	// Default: none (only base attributes: Id, Approved, email).
	// Override to: add Tenant, Plan, Role, or any custom:* attributes.
	GetCustomAttributes GetCustomAttributesFunc

	// OnUserConfirmed runs after successful confirmation.
	// Default: no-op.
	// Override to: create DB record, send welcome email, trigger workflows.
	OnUserConfirmed OnUserConfirmedFunc

	// GetNotification returns whether to send a notification and the payload.
	// Default: no notification.
	GetNotification GetNotificationFunc

	// =========================================================================
	// APP APPROVAL WORKFLOW HOOKS
	// For per-app approval (PostAuthentication + PreTokenGeneration triggers)
	// =========================================================================

	// AppClientConfig maps Cognito app client IDs to app metadata.
	// Used to determine which approval group to check for each app.
	AppClientConfig map[string]AppConfig

	// ShouldNotifyForApp returns notification for unapproved app access.
	// Default: no notification.
	// Override to: send Slack/email alerts when user needs approval.
	ShouldNotifyForApp ShouldNotifyForAppFunc

	// OnTokenDenied is called when token issuance is blocked.
	// Default: no-op.
	// Override to: log denials, track metrics.
	OnTokenDenied OnTokenDeniedFunc
}

// NewHandler creates a Handler with default hooks and AWS clients.
func NewHandler() *Handler {
	cfg, _ := config.LoadDefaultConfig(context.TODO(), config.WithRegion(os.Getenv("REGION")))
	return &Handler{
		cognitoClient: cognitoidentityprovider.NewFromConfig(cfg),
		snsClient:     sns.NewFromConfig(cfg),
		snsTopicArn:   os.Getenv("SNS_TOPIC_ARN"),

		// Default hooks
		ValidateSignUp:      DefaultValidateSignUp,
		GetCustomAttributes: DefaultGetCustomAttributes,
		OnUserConfirmed:     DefaultOnUserConfirmed,
		GetNotification:     DefaultGetNotification,

		// App approval hooks
		AppClientConfig:    make(map[string]AppConfig),
		ShouldNotifyForApp: DefaultShouldNotifyForApp,
		OnTokenDenied:      DefaultOnTokenDenied,
	}
}

// Handle is the main entry point - routes events and orchestrates hooks.
// Pass this to lambda.Start().
func (h *Handler) Handle(ctx context.Context, rawEvent map[string]interface{}) (interface{}, error) {
	triggerSource, ok := rawEvent["triggerSource"].(string)
	if !ok {
		log.Error().Msg("Missing triggerSource in event")
		return rawEvent, fmt.Errorf("missing triggerSource")
	}

	log.Info().Str("trigger", triggerSource).Msg("Processing trigger")

	switch {
	case strings.HasPrefix(triggerSource, "PreSignUp"):
		return h.handlePreSignUp(ctx, rawEvent)
	case strings.HasPrefix(triggerSource, "PostConfirmation"):
		return h.handlePostConfirmation(ctx, rawEvent)
	case strings.HasPrefix(triggerSource, "PostAuthentication"):
		return h.handlePostAuthentication(ctx, rawEvent)
	case strings.HasPrefix(triggerSource, "TokenGeneration"):
		return h.handlePreTokenGeneration(ctx, rawEvent)
	default:
		log.Warn().Str("trigger", triggerSource).Msg("Unhandled trigger source")
		return rawEvent, nil
	}
}

// =============================================================================
// PRE-SIGNUP HANDLING
// =============================================================================

func (h *Handler) handlePreSignUp(ctx context.Context, rawEvent map[string]interface{}) (interface{}, error) {
	event := h.parsePreSignUpEvent(rawEvent)

	isNativeSignup := event.TriggerSource == "PreSignUp_SignUp"
	isFederatedSignup := event.TriggerSource == "PreSignUp_ExternalProvider"

	log.Info().
		Str("trigger", event.TriggerSource).
		Str("username", event.UserName).
		Msg("PreSignUp")

	// Resolve email based on signup type
	if isNativeSignup {
		event.Email = event.UserName
	} else if isFederatedSignup {
		event.Email = event.UserAttributes["email"]
		if event.Email == "" {
			log.Error().Msg("Federated user has no email attribute")
			return rawEvent, fmt.Errorf("email is required")
		}
	}

	// HOOK: Validate signup (native only)
	if isNativeSignup && h.ValidateSignUp != nil {
		if err := h.ValidateSignUp(ctx, event); err != nil {
			log.Error().Err(err).Str("email", event.Email).Msg("Signup validation failed")
			return rawEvent, err
		}
	}

	// Check for existing user with same email
	existingUser, err := h.findUserByEmail(event.UserPoolID, event.Email)
	if err != nil {
		log.Error().Err(err).Msg("Error searching for existing user")
		return rawEvent, err
	}

	if isNativeSignup {
		// Native signup: reject if ANY user with same email exists
		if existingUser != nil {
			log.Error().Str("email", event.Email).Msg("Native signup rejected - user already exists")
			return rawEvent, fmt.Errorf("user already exists")
		}

		// Auto-confirm native users
		h.setAutoConfirm(rawEvent)
		log.Info().Str("email", event.Email).Msg("Auto-confirming native user")

	} else if isFederatedSignup && existingUser != nil {
		// Link federated identity to existing user
		if err := h.linkFederatedUser(ctx, event, existingUser); err != nil {
			return rawEvent, err
		}

		// Return error to prevent duplicate user creation
		return rawEvent, fmt.Errorf("linked to existing account")
	}

	// HOOK: Send notification for new users
	if h.GetNotification != nil {
		// Look up app config by client ID (nil if unknown)
		var appConfig *AppConfig
		if cfg, exists := h.AppClientConfig[event.CallerContext.ClientId]; exists {
			appConfig = &cfg
		}
		if payload, shouldSend := h.GetNotification(ctx, event, appConfig); shouldSend && payload != nil {
			h.sendNotification(payload)
		}
	}

	return rawEvent, nil
}

// =============================================================================
// POST-CONFIRMATION HANDLING
// =============================================================================

func (h *Handler) handlePostConfirmation(ctx context.Context, rawEvent map[string]interface{}) (interface{}, error) {
	event := h.parsePostConfirmationEvent(rawEvent)

	log.Info().
		Str("trigger", event.TriggerSource).
		Str("username", event.UserName).
		Msg("PostConfirmation")

	// Step 1: Base attributes (always applied)
	attrs := h.baseAttributes(event)

	// Step 2: Custom attributes (HOOK)
	if h.GetCustomAttributes != nil {
		custom, err := h.GetCustomAttributes(ctx, event)
		if err != nil {
			log.Error().Err(err).Msg("GetCustomAttributes hook failed")
			return rawEvent, fmt.Errorf("GetCustomAttributes hook failed: %w", err)
		}
		attrs = append(attrs, custom...)
	}

	// Step 3: Apply all attributes to Cognito
	if err := h.applyAttributes(ctx, event, attrs); err != nil {
		return rawEvent, err
	}

	// Step 4: Post-processing (HOOK)
	if h.OnUserConfirmed != nil {
		if err := h.OnUserConfirmed(ctx, event); err != nil {
			log.Error().Err(err).Msg("OnUserConfirmed hook failed")
			return rawEvent, fmt.Errorf("OnUserConfirmed hook failed: %w", err)
		}
	}

	return rawEvent, nil
}

// baseAttributes returns the standard attributes set for all confirmed users
func (h *Handler) baseAttributes(event *PostConfirmationEvent) []Attribute {
	attrs := []Attribute{
		{Name: "custom:Id", Value: identifier.NewId()},
	}

	// Set email if not already present (native users need it set from username)
	if event.UserAttributes["email"] == "" {
		attrs = append(attrs, Attribute{Name: "email", Value: event.UserName})
	}

	return attrs
}

// applyAttributes updates user attributes in Cognito
func (h *Handler) applyAttributes(ctx context.Context, event *PostConfirmationEvent, attrs []Attribute) error {
	if len(attrs) == 0 {
		return nil
	}

	cognitoAttrs := make([]types.AttributeType, len(attrs))
	for i, attr := range attrs {
		cognitoAttrs[i] = types.AttributeType{
			Name:  aws.String(attr.Name),
			Value: aws.String(attr.Value),
		}
		log.Info().Str("attr", attr.Name).Str("value", attr.Value).Msg("Setting attribute")
	}

	_, err := h.cognitoClient.AdminUpdateUserAttributes(ctx, &cognitoidentityprovider.AdminUpdateUserAttributesInput{
		UserPoolId:     aws.String(event.UserPoolID),
		Username:       aws.String(event.UserName),
		UserAttributes: cognitoAttrs,
	})
	if err != nil {
		log.Error().Err(err).Str("username", event.UserName).Msg("Failed to set attributes")
		return err
	}

	log.Info().Str("username", event.UserName).Msg("Successfully set attributes")
	return nil
}

// =============================================================================
// HELPER METHODS
// =============================================================================

func (h *Handler) parsePreSignUpEvent(rawEvent map[string]interface{}) *PreSignUpEvent {
	event := &PreSignUpEvent{
		RawEvent:       rawEvent,
		UserAttributes: make(map[string]string),
	}

	event.TriggerSource, _ = rawEvent["triggerSource"].(string)
	event.UserPoolID, _ = rawEvent["userPoolId"].(string)
	event.UserName, _ = rawEvent["userName"].(string)

	// Extract callerContext.clientId
	if callerContext, ok := rawEvent["callerContext"].(map[string]interface{}); ok {
		event.CallerContext.ClientId, _ = callerContext["clientId"].(string)
	}

	if request, ok := rawEvent["request"].(map[string]interface{}); ok {
		if userAttrs, ok := request["userAttributes"].(map[string]interface{}); ok {
			for k, v := range userAttrs {
				if str, ok := v.(string); ok {
					event.UserAttributes[k] = str
				}
			}
		}
	}

	return event
}

func (h *Handler) parsePostConfirmationEvent(rawEvent map[string]interface{}) *PostConfirmationEvent {
	event := &PostConfirmationEvent{
		RawEvent:       rawEvent,
		UserAttributes: make(map[string]string),
	}

	event.TriggerSource, _ = rawEvent["triggerSource"].(string)
	event.UserPoolID, _ = rawEvent["userPoolId"].(string)
	event.UserName, _ = rawEvent["userName"].(string)

	if request, ok := rawEvent["request"].(map[string]interface{}); ok {
		if userAttrs, ok := request["userAttributes"].(map[string]interface{}); ok {
			for k, v := range userAttrs {
				if str, ok := v.(string); ok {
					event.UserAttributes[k] = str
				}
			}
		}
	}

	event.Email = event.UserAttributes["email"]
	return event
}

func (h *Handler) setAutoConfirm(rawEvent map[string]interface{}) {
	if response, ok := rawEvent["response"].(map[string]interface{}); ok {
		response["autoConfirmUser"] = true
	}
}

func (h *Handler) findUserByEmail(userPoolID, email string) (*ExistingUser, error) {
	result, err := h.cognitoClient.ListUsers(context.TODO(), &cognitoidentityprovider.ListUsersInput{
		UserPoolId: aws.String(userPoolID),
		Filter:     aws.String(fmt.Sprintf("email = \"%s\"", email)),
	})
	if err != nil {
		return nil, err
	}

	if len(result.Users) == 0 {
		return nil, nil
	}

	user := &result.Users[0]
	return &ExistingUser{
		UserName: *user.Username,
		Email:    email,
		IsNative: *user.Username == email,
	}, nil
}

// providerNameMapping maps lowercase username prefixes to Cognito provider names.
// Cognito generates federated usernames with lowercase prefixes (e.g., "google_123456789")
// but AdminLinkProviderForUser requires exact match with configured provider name.
var providerNameMapping = map[string]string{
	"google":          "Google",
	"facebook":        "Facebook",
	"signinwithapple": "SignInWithApple",
	"loginwithamazon": "LoginWithAmazon",
}

func normalizeProviderName(prefix string) string {
	if mapped, ok := providerNameMapping[strings.ToLower(prefix)]; ok {
		return mapped
	}
	return prefix
}

// extractProviderInfo extracts provider name and subject from identities attribute or username
func extractProviderInfo(identitiesJSON string, username string) (string, string) {
	// First try to parse from identities attribute (most reliable)
	if identitiesJSON != "" {
		var identities []Identity
		if err := json.Unmarshal([]byte(identitiesJSON), &identities); err == nil && len(identities) > 0 {
			log.Info().
				Str("provider", identities[0].ProviderName).
				Str("userId", identities[0].UserId).
				Msg("Extracted provider from identities")
			return identities[0].ProviderName, identities[0].UserId
		}
	}

	// Fallback: parse from username (e.g., "google_123456789")
	parts := strings.SplitN(username, "_", 2)
	if len(parts) == 2 {
		providerName := normalizeProviderName(parts[0])
		log.Info().
			Str("raw", parts[0]).
			Str("normalized", providerName).
			Str("subject", parts[1]).
			Msg("Extracted provider from username")
		return providerName, parts[1]
	}

	return "", ""
}

func (h *Handler) linkFederatedUser(ctx context.Context, event *PreSignUpEvent, existingUser *ExistingUser) error {
	log.Info().
		Str("federated", event.UserName).
		Str("existing", existingUser.UserName).
		Bool("native", existingUser.IsNative).
		Msg("Linking federated user to existing")

	identitiesJSON := event.UserAttributes["identities"]
	providerName, providerSubject := extractProviderInfo(identitiesJSON, event.UserName)
	if providerName == "" || providerSubject == "" {
		log.Error().
			Str("username", event.UserName).
			Str("identities", identitiesJSON).
			Msg("Could not extract provider info")
		return fmt.Errorf("invalid federated username format")
	}

	log.Info().
		Str("provider", providerName).
		Str("subject", providerSubject).
		Msg("Linking with provider")

	_, err := h.cognitoClient.AdminLinkProviderForUser(ctx, &cognitoidentityprovider.AdminLinkProviderForUserInput{
		UserPoolId: aws.String(event.UserPoolID),
		DestinationUser: &types.ProviderUserIdentifierType{
			ProviderName:           aws.String("Cognito"),
			ProviderAttributeValue: aws.String(existingUser.UserName),
		},
		SourceUser: &types.ProviderUserIdentifierType{
			ProviderName:           aws.String(providerName),
			ProviderAttributeName:  aws.String("Cognito_Subject"),
			ProviderAttributeValue: aws.String(providerSubject),
		},
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to link federated user")
		return err
	}

	log.Info().
		Str("federated", event.UserName).
		Str("existing", existingUser.UserName).
		Msg("Successfully linked")
	return nil
}

func (h *Handler) sendNotification(payload *NotificationPayload) {
	if h.snsTopicArn == "" {
		log.Warn().Msg("SNS_TOPIC_ARN not configured, skipping notification")
		return
	}

	b, _ := json.Marshal(payload)
	_, err := h.snsClient.Publish(context.TODO(), &sns.PublishInput{
		TargetArn: aws.String(h.snsTopicArn),
		Message:   aws.String(string(b)),
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to publish to SNS topic")
	}
}

// =============================================================================
// POST-AUTHENTICATION HANDLING
// Fires after successful auth - sends notification if user not approved for app
// =============================================================================

func (h *Handler) handlePostAuthentication(ctx context.Context, rawEvent map[string]interface{}) (interface{}, error) {
	event := h.parsePostAuthenticationEvent(rawEvent)

	log.Info().
		Str("trigger", event.TriggerSource).
		Str("username", event.UserName).
		Str("clientId", event.CallerContext.ClientId).
		Msg("PostAuthentication")

	// Look up app config by client ID
	appConfig, exists := h.AppClientConfig[event.CallerContext.ClientId]
	if !exists {
		// Unknown app client - allow through without approval check
		log.Debug().Str("clientId", event.CallerContext.ClientId).Msg("Unknown app client, skipping approval check")
		return rawEvent, nil
	}

	// Check if user already in pending_apps (avoid duplicate notifications)
	pendingApps := event.UserAttributes["custom:PendingApps"]
	if containsApp(pendingApps, appConfig.AppName) {
		log.Info().
			Str("app", appConfig.AppName).
			Str("username", event.UserName).
			Msg("User already in pending_apps, skipping notification")
		return rawEvent, nil
	}

	// Check if user is in approved group
	isApproved, err := h.checkUserInGroup(ctx, event.UserPoolID, event.UserName, appConfig.ApprovedGroup)
	if err != nil {
		log.Error().Err(err).Msg("Failed to check group membership")
		return rawEvent, nil // Don't block auth on error, just log it
	}

	if isApproved {
		log.Info().
			Str("app", appConfig.AppName).
			Str("username", event.UserName).
			Msg("User is approved for app")
		return rawEvent, nil
	}

	// User not approved - add to pending_apps and notify
	newPendingApps := appendApp(pendingApps, appConfig.AppName)
	if err := h.updatePendingApps(ctx, event.UserPoolID, event.UserName, newPendingApps); err != nil {
		log.Error().Err(err).Msg("Failed to update pending_apps")
	}

	// HOOK: Send notification for unapproved app access
	if h.ShouldNotifyForApp != nil {
		if payload, shouldSend := h.ShouldNotifyForApp(ctx, event, &appConfig); shouldSend && payload != nil {
			h.sendNotification(payload)
		}
	}

	return rawEvent, nil
}

// =============================================================================
// PRE-TOKEN-GENERATION HANDLING
// Fires before token issuance - blocks token if user not in approved group
// =============================================================================

func (h *Handler) handlePreTokenGeneration(ctx context.Context, rawEvent map[string]interface{}) (interface{}, error) {
	event := h.parsePreTokenGenerationEvent(rawEvent)

	log.Info().
		Str("trigger", event.TriggerSource).
		Str("username", event.UserName).
		Str("clientId", event.CallerContext.ClientId).
		Msg("PreTokenGeneration")

	// Look up app config by client ID
	appConfig, exists := h.AppClientConfig[event.CallerContext.ClientId]
	if !exists {
		// Unknown app client - allow through without approval check
		log.Debug().Str("clientId", event.CallerContext.ClientId).Msg("Unknown app client, skipping approval check")
		return rawEvent, nil
	}

	// Check if user is in approved group
	isApproved, err := h.checkUserInGroup(ctx, event.UserPoolID, event.UserName, appConfig.ApprovedGroup)
	if err != nil {
		log.Error().Err(err).Msg("Failed to check group membership")
		// Fail closed - block token on error
		return rawEvent, fmt.Errorf("access denied: unable to verify approval status")
	}

	// Check pending_apps for cleanup
	pendingApps := event.UserAttributes["custom:PendingApps"]

	if isApproved {
		// User approved - clean up stale pending entry if exists
		if containsApp(pendingApps, appConfig.AppName) {
			newPendingApps := removeApp(pendingApps, appConfig.AppName)
			if err := h.updatePendingApps(ctx, event.UserPoolID, event.UserName, newPendingApps); err != nil {
				log.Error().Err(err).Msg("Failed to cleanup pending_apps")
			} else {
				log.Info().
					Str("app", appConfig.AppName).
					Str("username", event.UserName).
					Msg("Cleaned up pending_apps after approval")
			}
		}
		return rawEvent, nil
	}

	// User not approved - block token
	log.Warn().
		Str("app", appConfig.AppName).
		Str("username", event.UserName).
		Msg("Blocking token - user not approved")

	// HOOK: Notify about blocked token
	if h.OnTokenDenied != nil {
		if err := h.OnTokenDenied(ctx, event, &appConfig); err != nil {
			log.Error().Err(err).Msg("OnTokenDenied hook failed")
		}
	}

	return rawEvent, fmt.Errorf("User not approved for %s", appConfig.AppName)
}

// =============================================================================
// POST-AUTH / PRE-TOKEN HELPERS
// =============================================================================

func (h *Handler) parsePostAuthenticationEvent(rawEvent map[string]interface{}) *PostAuthenticationEvent {
	event := &PostAuthenticationEvent{
		RawEvent:       rawEvent,
		UserAttributes: make(map[string]string),
	}

	event.TriggerSource, _ = rawEvent["triggerSource"].(string)
	event.UserPoolID, _ = rawEvent["userPoolId"].(string)
	event.UserName, _ = rawEvent["userName"].(string)

	// Extract callerContext.clientId
	if callerContext, ok := rawEvent["callerContext"].(map[string]interface{}); ok {
		event.CallerContext.ClientId, _ = callerContext["clientId"].(string)
	}

	if request, ok := rawEvent["request"].(map[string]interface{}); ok {
		if userAttrs, ok := request["userAttributes"].(map[string]interface{}); ok {
			for k, v := range userAttrs {
				if str, ok := v.(string); ok {
					event.UserAttributes[k] = str
				}
			}
		}
	}

	event.Email = event.UserAttributes["email"]
	return event
}

func (h *Handler) parsePreTokenGenerationEvent(rawEvent map[string]interface{}) *PreTokenGenerationEvent {
	event := &PreTokenGenerationEvent{
		RawEvent:       rawEvent,
		UserAttributes: make(map[string]string),
	}

	event.TriggerSource, _ = rawEvent["triggerSource"].(string)
	event.UserPoolID, _ = rawEvent["userPoolId"].(string)
	event.UserName, _ = rawEvent["userName"].(string)

	// Extract callerContext.clientId
	if callerContext, ok := rawEvent["callerContext"].(map[string]interface{}); ok {
		event.CallerContext.ClientId, _ = callerContext["clientId"].(string)
	}

	if request, ok := rawEvent["request"].(map[string]interface{}); ok {
		if userAttrs, ok := request["userAttributes"].(map[string]interface{}); ok {
			for k, v := range userAttrs {
				if str, ok := v.(string); ok {
					event.UserAttributes[k] = str
				}
			}
		}

		// Extract groupConfiguration
		if groupConfig, ok := request["groupConfiguration"].(map[string]interface{}); ok {
			if groups, ok := groupConfig["groupsToOverride"].([]interface{}); ok {
				for _, g := range groups {
					if gs, ok := g.(string); ok {
						event.GroupConfig.GroupsToOverride = append(event.GroupConfig.GroupsToOverride, gs)
					}
				}
			}
		}
	}

	return event
}

// checkUserInGroup checks if user is member of a Cognito group
func (h *Handler) checkUserInGroup(ctx context.Context, userPoolID, username, groupName string) (bool, error) {
	result, err := h.cognitoClient.AdminListGroupsForUser(ctx, &cognitoidentityprovider.AdminListGroupsForUserInput{
		UserPoolId: aws.String(userPoolID),
		Username:   aws.String(username),
	})
	if err != nil {
		return false, err
	}

	for _, group := range result.Groups {
		if group.GroupName != nil && *group.GroupName == groupName {
			return true, nil
		}
	}
	return false, nil
}

// updatePendingApps updates the custom:PendingApps attribute
func (h *Handler) updatePendingApps(ctx context.Context, userPoolID, username, pendingApps string) error {
	_, err := h.cognitoClient.AdminUpdateUserAttributes(ctx, &cognitoidentityprovider.AdminUpdateUserAttributesInput{
		UserPoolId: aws.String(userPoolID),
		Username:   aws.String(username),
		UserAttributes: []types.AttributeType{
			{
				Name:  aws.String("custom:PendingApps"),
				Value: aws.String(pendingApps),
			},
		},
	})
	return err
}

// containsApp checks if app is in comma-separated list
func containsApp(pendingApps, appName string) bool {
	if pendingApps == "" {
		return false
	}
	apps := strings.Split(pendingApps, ",")
	for _, app := range apps {
		if strings.TrimSpace(app) == appName {
			return true
		}
	}
	return false
}

// appendApp adds app to comma-separated list
func appendApp(pendingApps, appName string) string {
	if pendingApps == "" {
		return appName
	}
	return pendingApps + "," + appName
}

// removeApp removes app from comma-separated list
func removeApp(pendingApps, appName string) string {
	if pendingApps == "" {
		return ""
	}
	apps := strings.Split(pendingApps, ",")
	result := make([]string, 0, len(apps))
	for _, app := range apps {
		if strings.TrimSpace(app) != appName {
			result = append(result, strings.TrimSpace(app))
		}
	}
	return strings.Join(result, ",")
}

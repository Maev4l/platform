# Platform IDP - Identity Provider

## Overview

Single Cognito User Pool managing authentication for multiple apps with per-app approval workflow.

## Authentication Flow

- Native signup: email as username, auto-confirmed
- Google OAuth: via Cognito Hosted UI
- Federated users auto-linked to existing native accounts (same email)

## Approval Workflow

1. User signs up/in to an app (e.g., cardgames-score)
2. If not in app's approval group -> SNS notification sent to admin
3. Token blocked until user added to group
4. Admin approves by adding user to Cognito group (e.g., `cardgames-score`)

## Cognito Lambda Triggers

| Trigger            | Purpose                                                                    |
| ------------------ | -------------------------------------------------------------------------- |
| PreSignUp          | Validate email, reject duplicates, auto-confirm, link federated identities |
| PostConfirmation   | Set custom:Id (UUID)                                                       |
| PostAuthentication | Send SNS notification if user not approved for app                         |
| PreTokenGeneration | Block token if not in app's group, cleanup PendingApps                     |

## Custom Attributes

- `custom:Id` - UUID (uppercase, no dashes)
- `custom:PendingApps` - comma-separated list of apps pending approval

## Apps

| App              | Client          | Group           |
| ---------------- | --------------- | --------------- |
| Card Games Score | cardgames-score | cardgames-score |

App client IDs stored in single SSM parameter: `platform.idp.app-clients` (JSON map: appName -> clientId)

## Adding a New App

1. Create `aws_cognito_user_pool_client` in cognito.tf
2. Create `aws_cognito_user_group` in cognito.tf
3. Add entry to `aws_ssm_parameter.app_clients` in cognito.tf

Example for "my-new-app":

```hcl
resource "aws_cognito_user_pool_client" "my_new_app" {
  name         = "my-new-app"
  user_pool_id = aws_cognito_user_pool.idp.id
  supported_identity_providers         = ["COGNITO", "Google"]
  callback_urls                        = ["https://my-new-app.isnan.eu/auth/callback", "http://localhost:3000/auth/callback"]
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  allowed_oauth_flows_user_pool_client = true
  depends_on                           = [aws_cognito_identity_provider.google]
}

resource "aws_cognito_user_group" "my_new_app" {
  name         = "my-new-app"
  user_pool_id = aws_cognito_user_pool.idp.id
  description  = "Approved users for My New App"
}

# Then add to aws_ssm_parameter.app_clients:
resource "aws_ssm_parameter" "app_clients" {
  value = jsonencode({
    "cardgames-score" = aws_cognito_user_pool_client.cardgames_score.id
    "my-new-app"      = aws_cognito_user_pool_client.my_new_app.id
  })
}
```

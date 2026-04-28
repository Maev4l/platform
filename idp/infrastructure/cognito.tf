# Cognito User Pool for Meal Planner authentication
resource "aws_cognito_user_pool" "idp" {
  name = "platform-idp"

  # Allow self-registration (pending admin approval via custom:Approved)
  admin_create_user_config {
    allow_admin_create_user_only = false
  }

  username_configuration {
    case_sensitive = false
  }

  # Lambda triggers for user management and per-app approval workflow
  lambda_config {
    pre_sign_up          = module.idp.function_arn
    post_confirmation    = module.idp.function_arn
    post_authentication  = module.idp.function_arn
    pre_token_generation = module.idp.function_arn
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "admin_only"
      priority = 1
    }
  }

  password_policy {
    minimum_length                   = 8
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    require_uppercase                = true
    temporary_password_validity_days = 7
  }

  user_pool_add_ons {
    advanced_security_mode = "OFF"
  }

  # Custom attributes
  schema {
    name                = "Id"
    attribute_data_type = "String"
    mutable             = true

    string_attribute_constraints {
      min_length = 1
      max_length = 50
    }
  }

  # Tracks apps user has requested but not yet approved for
  schema {
    name                = "PendingApps"
    attribute_data_type = "String"
    mutable             = true

    string_attribute_constraints {
      min_length = 0
      max_length = 500
    }
  }
}



# Cognito domain for hosted UI (custom domain)
resource "aws_cognito_user_pool_domain" "idp_domain" {
  domain          = "platform-idp-auth.isnan.eu"
  user_pool_id    = aws_cognito_user_pool.idp.id
  certificate_arn = data.aws_acm_certificate.wildcard_isnan.arn
}

# Google OAuth credentials from SSM Parameter Store
data "aws_ssm_parameter" "google_client_id" {
  name = "platform.google.client.id"
}

data "aws_ssm_parameter" "google_client_secret" {
  name = "platform.google.client.secret"
}

# Google Identity Provider
resource "aws_cognito_identity_provider" "google" {
  user_pool_id  = aws_cognito_user_pool.idp.id
  provider_name = "Google"
  provider_type = "Google"

  provider_details = {
    client_id        = data.aws_ssm_parameter.google_client_id.value
    client_secret    = data.aws_ssm_parameter.google_client_secret.value
    authorize_scopes = "openid email profile"
  }

  attribute_mapping = {
    email    = "email"
    name     = "name"
    username = "sub"
  }

  # AWS auto-populates additional OIDC fields in provider_details
  lifecycle {
    ignore_changes = [provider_details]
  }
}

# =============================================================================
# Card Games Score App
# =============================================================================

resource "aws_cognito_user_pool_client" "cardgames_score" {
  name         = "cardgames-score"
  user_pool_id = aws_cognito_user_pool.idp.id

  supported_identity_providers = ["COGNITO", "Google"]

  callback_urls = [
    "https://atout.isnan.eu/",
    "http://localhost:5176/"
  ]

  logout_urls = [
    "https://atout.isnan.eu/login",
    "http://localhost:5176/login"
  ]

  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  allowed_oauth_flows_user_pool_client = true

  # Cognito refresh tokens have absolute (non-sliding) expiry. 1 year keeps users
  # signed in long enough for daily-use scenarios while still rotating credentials yearly.
  refresh_token_validity = 365
  access_token_validity  = 60
  id_token_validity      = 60
  token_validity_units {
    refresh_token = "days"
    access_token  = "minutes"
    id_token      = "minutes"
  }

  depends_on = [aws_cognito_identity_provider.google]
}

resource "aws_cognito_user_group" "cardgames_score" {
  name         = "cardgames-score"
  user_pool_id = aws_cognito_user_pool.idp.id
  description  = "Approved users for Card Games Score"
}

# =============================================================================
# Visual Resumes
# =============================================================================

resource "aws_cognito_user_pool_client" "visual_resumes" {
  name         = "visual-resumes"
  user_pool_id = aws_cognito_user_pool.idp.id

  supported_identity_providers = ["COGNITO", "Google"]

  callback_urls = [
    "https://visual-resumes.isnan.eu/",
    "http://localhost:5178/"
  ]

  logout_urls = [
    "https://visual-resumes.isnan.eu/",
    "http://localhost:5178/"
  ]

  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  allowed_oauth_flows_user_pool_client = true

  # Cognito refresh tokens have absolute (non-sliding) expiry. 1 year keeps users
  # signed in long enough for daily-use scenarios while still rotating credentials yearly.
  refresh_token_validity = 365
  access_token_validity  = 60
  id_token_validity      = 60
  token_validity_units {
    refresh_token = "days"
    access_token  = "minutes"
    id_token      = "minutes"
  }

  depends_on = [aws_cognito_identity_provider.google]
}

resource "aws_cognito_user_group" "visual_resumes" {
  name         = "visual-resumes"
  user_pool_id = aws_cognito_user_pool.idp.id
  description  = "Approved users for visual-resumes"
}

# Store all app client IDs in single SSM parameter (breaks Terraform dependency cycle)
# Map format: appName -> clientId
resource "aws_ssm_parameter" "app_clients" {
  name = "platform.idp.app-clients"
  type = "String"
  value = jsonencode({
    "cardgames-score" = aws_cognito_user_pool_client.cardgames_score.id
    "visual-resumes"  = aws_cognito_user_pool_client.visual_resumes.id
  })
}

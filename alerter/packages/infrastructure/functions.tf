# Both alerter Lambdas: the notifier (SNS -> Slack, outbound) and the responder
# (Slack button clicks -> SNS, inbound). Grouped here so the two functions and
# their triggers live together.

# --- Notifier: consumes the alerting-events topic and posts to Slack ----------
module "alerter_function" {
  source        = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.8.0"
  function_name = "platform-notifier"
  zip = {
    filename = "../notifier/dist/notifier.zip"
    runtime  = "provided.al2023"
    handler  = "bootstrap"
    hash     = filebase64sha256("../notifier/bin/bootstrap")
  }
  architecture = "arm64"

  environment_variables = {
    "SLACK_CHANNEL_ID" : "C0544QDSXKQ"
    # SSM parameter NAME (not the secret value) - Lambda fetches the token at runtime
    "SLACK_TOKEN" : local.slack_token_param_name
  }

  # Attach SSM read policy to Lambda execution role
  additional_policy_arns = [aws_iam_policy.alerter_ssm_policy.arn]
}

module "sns_trigger" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-trigger-sns?ref=v1.8.0"

  function_name = module.alerter_function.function_name
  function_arn  = module.alerter_function.function_arn
  topic_arn     = aws_sns_topic.alerting_events.arn
}

# --- Responder: receives Slack button clicks over a public Function URL -------
module "responder_function" {
  source        = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.8.0"
  function_name = "platform-notifier-responder"
  zip = {
    filename = "../responder/dist/responder.zip"
    runtime  = "provided.al2023"
    handler  = "bootstrap"
    hash     = filebase64sha256("../responder/bin/bootstrap")
  }
  architecture = "arm64"

  # The Function URL is public (auth NONE), so every request — including unsigned
  # floods rejected at the signature check — invokes the Lambda. A small reserved
  # concurrency caps this function's cost/blast radius AND guarantees it can never
  # starve the account's shared pool. Human button-clicks need only a few slots.
  reserved_concurrent_executions = 5

  # Env vars carry SSM parameter NAMES (not secret values) + the non-secret topic
  # ARN; the Lambda fetches the signing secret + operators from SSM at startup.
  environment_variables = {
    "SLACK_SIGNING_SECRET" : local.slack_signing_secret_param_name # SSM name
    "SLACK_OPERATORS" : local.slack_operators_param_name           # SSM name
    "RESPONSES_TOPIC_ARN" : aws_sns_topic.alerting_responses.arn
  }

  additional_policy_arns = [aws_iam_policy.responder.arn]
}

# Public HTTPS endpoint for Slack's interactivity request URL. Security is the
# Slack request signature (verified in-code), so no AWS auth on the URL itself.
resource "aws_lambda_function_url" "responder" {
  function_name      = module.responder_function.function_name
  authorization_type = "NONE"
}

# AuthType NONE still requires an explicit invoke permission.
resource "aws_lambda_permission" "responder_url" {
  statement_id           = "AllowFunctionURLInvoke"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = module.responder_function.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}

# IAM policy allowing Lambda to read the Slack token from SSM
# Default KMS key (aws/ssm) automatically grants decrypt to principals with ssm:GetParameter
data "aws_iam_policy_document" "ssm_read_slack_token" {
  statement {
    effect = "Allow"
    actions = [
      "ssm:GetParameter"
    ]
    resources = [
      "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${local.slack_token_param_name}"
    ]
  }
}

resource "aws_iam_policy" "alerter_ssm_policy" {
  name        = "platform-notifier-ssm-policy"
  description = "Allow alerter Lambda to read Slack token from SSM"
  policy      = data.aws_iam_policy_document.ssm_read_slack_token.json
}

# Responder: read its two SSM secrets and publish decisions to the responses topic.
data "aws_iam_policy_document" "responder" {
  statement {
    effect  = "Allow"
    actions = ["ssm:GetParameter"]
    resources = [
      "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${local.slack_signing_secret_param_name}",
      "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${local.slack_operators_param_name}",
    ]
  }
  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerting_responses.arn]
  }
}

resource "aws_iam_policy" "responder" {
  name        = "platform-notifier-responder-policy"
  description = "Allow responder Lambda to read SSM secrets and publish responses"
  policy      = data.aws_iam_policy_document.responder.json
}

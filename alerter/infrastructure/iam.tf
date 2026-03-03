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
  name        = "platform-alerter-ssm-policy"
  description = "Allow alerter Lambda to read Slack token from SSM"
  policy      = data.aws_iam_policy_document.ssm_read_slack_token.json
}

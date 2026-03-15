


data "aws_iam_policy_document" "idp" {
  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [data.aws_sns_topic.alerting.arn]
  }

  statement {
    effect = "Allow"
    actions = [
      "cognito-idp:AdminGetUser",
      "cognito-idp:AdminUpdateUserAttributes",
      "cognito-idp:AdminLinkProviderForUser",
      "cognito-idp:ListUsers",
      "cognito-idp:AdminListGroupsForUser",
    ]
    resources = ["arn:aws:cognito-idp:${var.region}:${local.account_id}:userpool/${aws_cognito_user_pool.idp.id}"]
  }

  # Read app client IDs from SSM Parameter Store
  statement {
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${var.region}:${local.account_id}:parameter/platform.idp.app-clients"]
  }
}

resource "aws_iam_policy" "idp" {
  name   = "platform-idp"
  policy = data.aws_iam_policy_document.idp.json
}

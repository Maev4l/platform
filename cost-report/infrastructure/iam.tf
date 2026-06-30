# Cost Explorer is a global (resource-less) API — ce:* actions only support "*".
# sns:Publish is scoped to the alerting topic.
data "aws_iam_policy_document" "cost_report" {
  statement {
    sid    = "CostExplorerRead"
    effect = "Allow"
    actions = [
      "ce:GetCostAndUsage",
      "ce:GetCostForecast",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "PublishAlert"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [data.aws_sns_topic.alerting.arn]
  }
}

resource "aws_iam_policy" "cost_report" {
  name        = "platform-cost-report-policy"
  description = "Allow cost-report Lambda to read Cost Explorer and publish alerts"
  policy      = data.aws_iam_policy_document.cost_report.json
}

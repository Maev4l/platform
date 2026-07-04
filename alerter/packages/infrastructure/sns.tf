resource "aws_sns_topic" "alerting_events" {
  name = "alerting-events"
}

# Decisions from button clicks. The alerter owns this topic; producers subscribe
# their own Lambda/SQS (with a {"source":[...]} filter policy) from their stacks.
resource "aws_sns_topic" "alerting_responses" {
  name = "alerting-responses"
}

# Same-account producers may self-subscribe without the alerter knowing them.
data "aws_iam_policy_document" "responses_topic_policy" {
  statement {
    sid     = "AllowAccountSubscribe"
    effect  = "Allow"
    actions = ["sns:Subscribe"]
    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.account_id]
    }
    resources = [aws_sns_topic.alerting_responses.arn]
  }
}

resource "aws_sns_topic_policy" "alerting_responses" {
  arn    = aws_sns_topic.alerting_responses.arn
  policy = data.aws_iam_policy_document.responses_topic_policy.json
}

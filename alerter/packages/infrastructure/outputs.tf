output "responder_public_url" {
  description = "Slack app Interactivity Request URL (stable custom domain fronting the responder)"
  value       = "https://${local.responder_domain}/"
}

output "responder_function_url" {
  description = "Raw Lambda Function URL (CloudFront origin only; AWS_IAM — not directly invokable). For debugging."
  value       = aws_lambda_function_url.responder.function_url
}

output "responses_topic_arn" {
  description = "SNS topic producers subscribe to for button decisions"
  value       = aws_sns_topic.alerting_responses.arn
}

output "responder_function_url" {
  description = "Set this as the Slack app Interactivity Request URL"
  value       = aws_lambda_function_url.responder.function_url
}

output "responses_topic_arn" {
  description = "SNS topic producers subscribe to for button decisions"
  value       = aws_sns_topic.alerting_responses.arn
}

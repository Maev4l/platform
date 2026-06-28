resource "aws_athena_workgroup" "monitoring" {
  name          = "monitoring"
  force_destroy = true

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = false
    bytes_scanned_cutoff_per_query     = 5 * 1024 * 1024 * 1024 # 5 GB cost guardrail

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/results/"
    }
  }
}

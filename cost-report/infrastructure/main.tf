terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  backend "s3" {
    bucket       = "global-tf-states"
    key          = "platform/cost-report.tfstate"
    region       = "eu-central-1"
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      application = "platform-cost-report"
      owner       = "terraform"
    }
  }
}

# Existing alerting pipeline topic this Lambda publishes to.
data "aws_sns_topic" "alerting" {
  name = "alerting-events"
}

module "cost_report_function" {
  source        = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.8.1"
  function_name = "platform-cost-report"
  zip = {
    filename = "../function/dist/cost-report.zip"
    runtime  = "provided.al2023"
    handler  = "bootstrap"
    hash     = filebase64sha256("../function/bin/bootstrap")
  }
  architecture = "arm64"

  environment_variables = {
    "SNS_TOPIC_ARN" : data.aws_sns_topic.alerting.arn
  }

  additional_policy_arns = [aws_iam_policy.cost_report.arn]
}

module "weekly_schedule" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-trigger-scheduler?ref=v1.8.1"

  function_name = module.cost_report_function.function_name
  function_arn  = module.cost_report_function.function_arn

  schedule_name        = "platform-cost-report-weekly"
  description          = "Weekly AWS cost report to Slack (Monday 06:00 UTC)"
  schedule_expression  = "cron(0 6 ? * MON *)"
  timezone             = "UTC"
  flexible_time_window = 0
}

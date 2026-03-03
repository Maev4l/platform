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
    key          = "platform/alerter.tfstate"
    region       = "eu-central-1"
    use_lockfile = true # S3 native locking (no DynamoDB needed)
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      application = "alexandria"
      owner       = "terraform"
    }
  }
}

locals {
  slack_token_param_name = "slack.alerting.token"
}

data "aws_caller_identity" "current" {}

module "alerter_function" {
  source        = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.4.1"
  function_name = "platform-alerter"
  zip = {
    filename = "../function/dist/alerter.zip"
    runtime  = "provided.al2023"
    handler  = "bootstrap"
  }
  architecture = "arm64"

  environment_variables = {
    "SLACK_CHANNEL_ID" : "C0544QDSXKQ"
    # SSM parameter name - Lambda fetches the actual token at runtime
    "SLACK_TOKEN" : local.slack_token_param_name
  }

  # Attach SSM read policy to Lambda execution role
  additional_policy_arns = [aws_iam_policy.alerter_ssm_policy.arn]
}

module "sns_trigger" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-trigger-sns?ref=v1.4.1"

  function_name = module.alerter_function.function_name
  function_arn  = module.alerter_function.function_arn
  topic_arn     = aws_sns_topic.alerting_events.arn
}

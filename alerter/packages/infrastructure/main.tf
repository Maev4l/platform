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
      application = "platform-alerter"
      owner       = "terraform"
    }
  }
}

# CloudFront viewer certificates must live in us-east-1, so the responder's custom
# domain (cdn.tf) resolves its ACM cert through this aliased provider.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      application = "platform-alerter"
      owner       = "terraform"
    }
  }
}

locals {
  slack_token_param_name          = "slack.alerting.token"
  slack_signing_secret_param_name = "slack.alerting.signing_secret"
  slack_operators_param_name      = "slack.alerting.operators"
}

data "aws_caller_identity" "current" {}

# Lambda functions (notifier + responder) live in functions.tf.

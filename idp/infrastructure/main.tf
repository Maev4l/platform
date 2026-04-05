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
    key          = "platform/idp.tfstate"
    region       = "eu-central-1"
    use_lockfile = true # S3 native locking (no DynamoDB needed)
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      application = "platform-idp"
      owner       = "terraform"
    }
  }
}

# Provider alias for CloudFront certificate (must be in us-east-1)
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      application = "meal-planner"
      owner       = "terraform"
    }
  }
}


data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}


module "idp" {
  source        = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.6.0"
  function_name = "platform-idp"
  zip = {
    filename = "../function/dist/idp.zip"
    runtime  = "provided.al2023"
    handler  = "bootstrap"
    hash     = filebase64sha256("../function/bin/bootstrap")
  }
  architecture = "arm64"

  environment_variables = {
    REGION        = var.region
    SNS_TOPIC_ARN = data.aws_sns_topic.alerting.arn
  }

  additional_policy_arns = [aws_iam_policy.idp.arn]
}


module "idp_trigger" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-trigger-cognito?ref=v1.6.0"

  function_name = module.idp.function_name
  function_arn  = module.idp.function_arn

  user_pool_id = aws_cognito_user_pool.idp.id
}

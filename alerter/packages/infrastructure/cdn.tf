# Stable custom domain for the responder webhook:
#   platform-slack-responder.isnan.eu -> CloudFront -> responder Lambda Function URL.
#
# Why CloudFront: (1) a stable URL decoupled from the AWS-generated Function URL id
# (which only changes if the function is recreated), so Slack's Request URL never has
# to be reconfigured; (2) a natural place to attach WAF/rate-limiting later.
#
# NO OAC / no origin signing. CloudFront OAC cannot SigV4-sign a POST *body* to a
# Lambda Function URL, so an AWS_IAM origin rejects every Slack interactivity POST
# with InvalidSignatureException (403). The Function URL is therefore AuthType NONE
# and CloudFront just proxies; the request is authenticated in-code by the responder's
# Slack signing-secret HMAC (verifySignature) + operator allow-list, which is the
# correct control for a Slack webhook (unsigned requests get 401). The raw *.lambda-url
# is publicly reachable but useless without a valid Slack signature. Operator must
# verify the Slack interactivity POST succeeds through this domain at first deploy.

locals {
  responder_domain = "platform-slack-responder.isnan.eu"
}

# CloudFront viewer certs must be in us-east-1 (see the aliased provider in main.tf).
data "aws_acm_certificate" "wildcard" {
  provider    = aws.us_east_1
  domain      = "*.isnan.eu"
  statuses    = ["ISSUED"]
  most_recent = true
}

data "aws_route53_zone" "isnan" {
  name = "isnan.eu"
}

resource "aws_cloudfront_distribution" "responder" {
  enabled         = true
  comment         = "platform-notifier-responder (Slack interactivity)"
  aliases         = [local.responder_domain]
  price_class     = "PriceClass_100" # NA + EU edges are enough for a Slack webhook
  is_ipv6_enabled = true

  origin {
    origin_id   = "responder-lambda-url"
    domain_name = replace(replace(aws_lambda_function_url.responder.function_url, "https://", ""), "/", "")

    custom_origin_config {
      origin_protocol_policy = "https-only"
      http_port              = 80
      https_port             = 443
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "responder-lambda-url"
    viewer_protocol_policy = "https-only"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]

    # Managed "CachingDisabled" — a webhook response must never be cached.
    cache_policy_id = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
    # Managed "AllViewerExceptHostHeader" — forward the Slack signature headers + the
    # request body, but NOT Host (a Lambda Function URL origin rejects a foreign Host).
    origin_request_policy_id = "b689b0a8-53d0-40ab-baf2-68738e2966ac"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = data.aws_acm_certificate.wildcard.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

resource "aws_route53_record" "responder" {
  zone_id = data.aws_route53_zone.isnan.zone_id
  name    = local.responder_domain
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.responder.domain_name
    zone_id                = aws_cloudfront_distribution.responder.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "responder_aaaa" {
  zone_id = data.aws_route53_zone.isnan.zone_id
  name    = local.responder_domain
  type    = "AAAA"

  alias {
    name                   = aws_cloudfront_distribution.responder.domain_name
    zone_id                = aws_cloudfront_distribution.responder.hosted_zone_id
    evaluate_target_health = false
  }
}

# Route53 hosted zone and DNS records

data "aws_route53_zone" "isnan" {
  name = "isnan.eu"
}

# Cognito custom domain for Google OAuth
resource "aws_route53_record" "cognito_auth" {
  zone_id = data.aws_route53_zone.isnan.zone_id
  name    = "platform-idp-auth.isnan.eu"
  type    = "A"

  alias {
    name                   = aws_cognito_user_pool_domain.idp_domain.cloudfront_distribution_arn
    zone_id                = "Z2FDTNDATAQYW2" # CloudFront fixed zone ID
    evaluate_target_health = false
  }
}

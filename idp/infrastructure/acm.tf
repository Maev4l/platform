# ACM certificate data source for custom domain
# CloudFront requires certificates in us-east-1

data "aws_acm_certificate" "wildcard_isnan" {
  provider    = aws.us_east_1
  domain      = "*.isnan.eu"
  statuses    = ["ISSUED"]
  most_recent = true
}

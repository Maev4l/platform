# CloudFront log sources to query.
#
# Each key is the source's display name in the UI selector AND the base for its
# Glue table name (table = key with '-' replaced by '_'). `bucket` + `prefix`
# point at the per-app CloudFront standard-logging v2 destination, which lands
# objects under <prefix>/year=YYYY/month=MM/day=DD/.
#
# Bucket convention across the platform: <app>-cloudfront-logs-<account-id>.
log_sources = {
  "alexandria"           = { bucket = "alexandria-cloudfront-logs-671123374425", prefix = "raw/app" }
  "meal-planner"         = { bucket = "meal-planner-cloudfront-logs-671123374425", prefix = "raw/app" }
  "brigitte-leroux-site" = { bucket = "brigitte-le-roux-website-cloudfront-logs-671123374425", prefix = "raw/site" }
  "brigitte-leroux-cms"  = { bucket = "brigitte-le-roux-website-cloudfront-logs-671123374425", prefix = "raw/cms" }
  "visual-resumes"       = { bucket = "visual-resumes-cloudfront-logs-671123374425", prefix = "raw/app" }
}

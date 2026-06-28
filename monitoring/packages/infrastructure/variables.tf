variable "region" {
  type    = string
  default = "eu-central-1"
}

# Map of source name -> { bucket, prefix }. Example:
#   bl-cms  = { bucket = "<bucket>", prefix = "raw/cms" }
#   bl-site = { bucket = "<bucket>", prefix = "raw/site" }
variable "log_sources" {
  type = map(object({
    bucket = string
    prefix = string
  }))
  default = {}
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      application = "platform-monitoring"
      owner       = "terraform"
    }
  }
}

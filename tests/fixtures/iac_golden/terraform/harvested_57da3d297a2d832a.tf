resource "aws_lb" "main" {
  name = "main-lb"
  internal = false
  enable_deletion_protection = true

  access_logs {
    bucket  = "my-lb-logs"
    enabled = true
  }
}

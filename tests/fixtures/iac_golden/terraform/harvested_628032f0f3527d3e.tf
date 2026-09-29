
resource "aws_s3_bucket" "logs" {
  bucket = "ops-logs"
  acl    = "public-read"
}

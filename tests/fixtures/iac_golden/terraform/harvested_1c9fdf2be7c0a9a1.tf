resource "aws_cloudtrail" "main" {
  name           = "main-trail"
  s3_bucket_name = "my-bucket"
}

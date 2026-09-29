resource "aws_cloudtrail" "main" {
  name                       = "main-trail"
  s3_bucket_name             = "my-bucket"
  is_multi_region_trail      = true
  enable_log_file_validation = true
}

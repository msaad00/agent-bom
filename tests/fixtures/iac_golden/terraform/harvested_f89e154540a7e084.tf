resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
  acl    = "public-read"
}

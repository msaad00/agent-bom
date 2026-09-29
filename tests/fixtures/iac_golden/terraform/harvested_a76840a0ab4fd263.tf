resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"

  logging {
    target_bucket = "my-log-bucket"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}

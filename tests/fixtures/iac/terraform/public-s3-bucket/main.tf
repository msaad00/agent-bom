# Intentionally vulnerable regression fixture.
# Encryption does not make public object access safe; TF-SEC-002 must still
# flag this bucket because acl = "public-read" exposes storage publicly.
resource "aws_s3_bucket" "training_data" {
  bucket = "agent-bom-public-training-data"
  acl    = "public-read"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}

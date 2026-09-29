resource "aws_secretsmanager_secret" "db_pass" {
  name       = "db-password"
  kms_key_id = "arn:aws:kms:us-east-1:123456789:key/abc"
}

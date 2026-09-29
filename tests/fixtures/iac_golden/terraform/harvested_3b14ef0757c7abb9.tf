resource "aws_secretsmanager_secret" "db_pass" {
  name = "db-password"
}

resource "aws_ssm_parameter" "secret" {
  name  = "/app/secret"
  type  = "SecureString"
  value = "supersecret"
}

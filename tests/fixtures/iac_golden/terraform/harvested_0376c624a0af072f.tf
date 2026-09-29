resource "aws_db_instance" "db" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  storage_encrypted = true
  backup_retention_period = 3
  enabled_cloudwatch_logs_exports = ["audit"]
}

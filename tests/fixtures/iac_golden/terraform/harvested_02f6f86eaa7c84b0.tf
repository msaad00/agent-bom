resource "aws_db_instance" "db" {
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  storage_encrypted   = true
  deletion_protection = true
  enabled_cloudwatch_logs_exports = ["audit"]
}

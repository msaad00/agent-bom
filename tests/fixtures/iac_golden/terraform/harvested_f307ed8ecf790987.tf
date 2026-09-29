resource "aws_db_instance" "db" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  storage_encrypted = true
  multi_az = true
  enabled_cloudwatch_logs_exports = ["audit"]
}

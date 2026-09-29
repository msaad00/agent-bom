resource "aws_db_instance" "db" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
}

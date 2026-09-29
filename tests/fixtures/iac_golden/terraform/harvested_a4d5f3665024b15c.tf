resource "aws_default_security_group" "default" {
  vpc_id = "vpc-123"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

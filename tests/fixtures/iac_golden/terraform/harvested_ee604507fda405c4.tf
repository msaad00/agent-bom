resource "aws_lb" "main" {
  name     = "main-lb"
  internal = false
}

resource "aws_wafv2_web_acl_association" "main" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = "arn:aws:wafv2:us-east-1:123:regional/webacl/example/abc"
}

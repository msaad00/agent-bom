resource "aws_iam_policy" "broad" {
  name = "broad"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*"
  }]
}
EOF
}

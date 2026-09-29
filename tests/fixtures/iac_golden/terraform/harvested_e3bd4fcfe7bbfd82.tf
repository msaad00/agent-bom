resource "aws_lambda_function" "fn" {
  function_name = "my-fn"
  handler       = "index.handler"
  runtime       = "python3.12"

  vpc_config {
    subnet_ids         = ["subnet-123"]
    security_group_ids = ["sg-123"]
  }

  dead_letter_config {
    target_arn = "arn:aws:sqs:us-east-1:123456789:dlq"
  }
}

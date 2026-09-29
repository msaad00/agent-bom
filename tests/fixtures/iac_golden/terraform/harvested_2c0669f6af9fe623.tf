resource "aws_lambda_function" "fn" {
  function_name = "my-fn"
  handler       = "index.handler"
  runtime       = "python3.12"

  environment {
    variables = {
      LOG_LEVEL = "info"
    }
  }
}

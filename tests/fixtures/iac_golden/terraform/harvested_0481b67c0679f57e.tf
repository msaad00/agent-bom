
resource "aws_sagemaker_endpoint" "infer" {
  name                 = "infer"
  endpoint_config_name = "infer-cfg"
}

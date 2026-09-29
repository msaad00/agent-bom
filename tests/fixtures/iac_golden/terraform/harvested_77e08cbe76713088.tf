
resource "aws_bedrock_model_invocation_logging_configuration" "this" {
  logging_config {
    text_data_delivery_enabled  = false
    image_data_delivery_enabled = false
  }
}

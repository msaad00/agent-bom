resource "aws_sns_topic" "alerts" {
  name              = "alerts"
  kms_master_key_id = "alias/my-key"
}

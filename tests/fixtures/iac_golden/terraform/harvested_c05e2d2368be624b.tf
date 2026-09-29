resource "aws_sqs_queue" "jobs" {
  name              = "jobs"
  kms_master_key_id = "alias/my-key"
}

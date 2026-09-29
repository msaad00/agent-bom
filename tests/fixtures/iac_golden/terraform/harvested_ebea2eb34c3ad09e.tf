
resource "aws_sagemaker_training_job" "train" {
  name = "train-fraud"
  input_data_config {
    channel_name = "training"
    data_source { s3_data_source { s3_uri = "s3://my-training-bucket/data" } }
  }
}

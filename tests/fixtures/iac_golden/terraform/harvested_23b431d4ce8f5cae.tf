
resource "aws_s3_bucket_policy" "wandb_models" {
  bucket = "wandb-artifact-store"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Sid       = "AllowAll",
      Effect    = "Allow",
      Principal = "*",
      Action    = ["s3:GetObject"],
      Resource  = "arn:aws:s3:::wandb-artifact-store/*"
    }]
  })
}

/*
resource "aws_s3_bucket" "commented_out" {
  acl = "public-read"
}
*/
# resource "aws_kms_key" "hash_commented" {}
// resource "aws_kms_key" "slash_commented" {}

resource "aws_s3_bucket" "good_bucket" {
  bucket = "good"
  acl    = "private"
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
  versioning {
    enabled = true
  }
  logging {
    target_bucket = "logs"
  }
}

resource "aws_s3_bucket_public_access_block" "good_bucket" {
  bucket = "good"
}

resource "aws_flow_log" "vpc" {
  vpc_id = "vpc-1"
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_security_group" "web_only" {
  ingress {
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_eks_cluster" "eks" {
  encryption_config {
    resources = ["secrets"]
  }
}

resource "aws_lambda_function" "fn" {
  dead_letter_config {
    target_arn = "arn"
  }
  vpc_config {
    subnet_ids = []
  }
}

resource "aws_elasticache_replication_group" "redis" {
  transit_encryption_enabled = true
}

resource "aws_dynamodb_table" "pitr" {
  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_api_gateway_stage" "stage" {
  access_log_settings {
    destination_arn = "arn"
  }
}

resource "aws_kms_key" "rotated" {
  enable_key_rotation = true
}

resource "aws_ebs_volume" "vol" {
  encrypted = true
}

resource "aws_ebs_snapshot" "snap" {
  encrypted = true
}

resource "aws_lb" "lb" {
  enable_deletion_protection = true
  access_logs {
    bucket  = "logs"
    enabled = true
  }
}

resource "aws_wafv2_web_acl_association" "waf" {
  resource_arn = "arn"
}

resource "aws_cloudtrail" "trail" {
  is_multi_region_trail      = true
  enable_log_file_validation = true
}

resource "aws_sns_topic" "topic" {
  kms_master_key_id = "alias/x"
}

resource "aws_sqs_queue" "queue" {
  kms_master_key_id = "alias/x"
}

resource "aws_ecr_repository" "repo" {
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecs_task_definition" "task" {
  network_mode = "awsvpc"
  container_definitions = jsonencode([{ name = "app", user = "1000" }])
}

resource "aws_secretsmanager_secret" "secret" {
  kms_key_id = "alias/x"
}

resource "aws_ssm_parameter" "param" {
  type   = "SecureString"
  key_id = "alias/x"
}

resource "aws_default_security_group" "default" {
  vpc_id = "vpc-1"
}

resource "aws_opensearch_domain" "os" {
  encrypt_at_rest {
    enabled = true
  }
  node_to_node_encryption {
    enabled = true
  }
}

resource "aws_redshift_cluster" "rs" {
  encrypted = true
}

resource "aws_guardduty_detector" "gd" {
  enable = true
}

resource "aws_no_brace" "dangling"

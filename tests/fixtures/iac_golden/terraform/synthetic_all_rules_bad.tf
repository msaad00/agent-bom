resource "aws_s3_bucket" "bad_bucket" {
  bucket = "bad"
  acl    = "public-read-write"
  versioning {
    enabled = false
  }
}

resource "aws_s3_bucket" "no_versioning" {
  bucket = "nov"
  acl    = "public-read"
}

resource "aws_security_group" "wide_open" {
  name = "wide"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8", "0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "rule_v4" {
  type        = "ingress"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "rule_v6" {
  type             = "ingress"
  ipv6_cidr_blocks = ["::/0"]
}

resource "aws_iam_policy" "star_json" {
  policy = <<EOF
{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
EOF
}

resource "aws_iam_role_policy" "star_action_only" {
  policy = <<EOF
{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::x"}]}
EOF
}

resource "aws_iam_group_policy" "hcl_star" {
  actions   = ["*"]
  resources = ["arn:aws:s3:::x"]
}

resource "aws_iam_user_policy" "clean_user" {
  actions = ["s3:GetObject"]
}

resource "aws_db_instance" "db_unencrypted" {
  storage_encrypted       = false
  publicly_accessible     = true
  backup_retention_period = 3
}

resource "aws_db_instance" "db_unset" {
  engine = "postgres"
}

resource "aws_db_instance" "db_good" {
  storage_encrypted               = true
  enabled_cloudwatch_logs_exports = ["postgresql"]
  backup_retention_period         = 14
  multi_az                        = true
  deletion_protection             = true
}

resource "aws_rds_cluster" "cluster_zero_backup" {
  storage_encrypted       = true
  backup_retention_period = 0
}

resource "aws_key_pair" "hardcoded" {
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ user@example"
}

resource "aws_instance" "no_imds" {
  ami = "ami-123"
}

resource "aws_instance" "imds_optional" {
  ami = "ami-123"
  metadata_options {
    http_tokens = "optional"
  }
}

resource "aws_instance" "imds_required" {
  ami = "ami-123"
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_cloudwatch_log_group" "no_retention" {
  name = "x"
}

resource "aws_cloudwatch_log_group" "zero_retention" {
  name              = "y"
  retention_in_days = 0
}

resource "aws_cloudwatch_log_group" "good_retention" {
  name              = "z"
  retention_in_days = 90
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_eks_cluster" "eks" {
  name = "eks"
}

resource "aws_lambda_function" "fn" {
  function_name = "fn"
  environment {
    variables = {
      db_password = "hunter2hunter2"
    }
  }
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id = "r"
}

resource "aws_elasticache_cluster" "memcache" {
  cluster_id = "m"
}

resource "aws_dynamodb_table" "no_pitr" {
  name = "t1"
}

resource "aws_dynamodb_table" "pitr_disabled" {
  name = "t2"
  point_in_time_recovery {
    enabled = false
  }
}

resource "aws_api_gateway_stage" "stage_v1" {
  stage_name = "prod"
}

resource "aws_apigatewayv2_stage" "stage_v2" {
  name = "prod"
}

resource "aws_kms_key" "no_rotation" {
  description = "k"
}

resource "aws_ebs_volume" "vol" {
  size = 10
}

resource "aws_ebs_snapshot" "snap" {
  volume_id = "vol-1"
}

resource "aws_lb" "lb_no_logs" {
  name = "lb"
}

resource "aws_alb" "alb_logs_disabled" {
  name = "alb"
  access_logs {
    bucket  = "logs"
    enabled = false
  }
}

resource "aws_elb" "classic" {
  name = "elb"
}

resource "aws_cloudtrail" "trail" {
  name = "t"
}

resource "aws_sns_topic" "topic" {
  name = "t"
}

resource "aws_sqs_queue" "queue" {
  name = "q"
}

resource "aws_ecr_repository" "repo_no_scan" {
  name = "r1"
}

resource "aws_ecr_repository" "repo_scan_off" {
  name = "r2"
  image_scanning_configuration {
    scan_on_push = false
  }
}

resource "aws_ecs_task_definition" "task_host" {
  family       = "t"
  network_mode = "host"
  container_definitions = jsonencode([{ name = "app", image = "nginx" }])
}

resource "aws_ecs_task_definition" "task_root_user" {
  family = "t2"
  container_definitions = jsonencode([{ name = "app", user = "root" }])
}

resource "aws_secretsmanager_secret" "secret" {
  name = "s"
}

resource "aws_ssm_parameter" "param" {
  name  = "p"
  type  = "SecureString"
  value = "v"
}

resource "aws_default_security_group" "default" {
  vpc_id = "vpc-1"
  ingress {
    protocol = -1
  }
  egress {
    protocol = -1
  }
}

resource "aws_elasticsearch_domain" "es" {
  domain_name = "es"
  encrypt_at_rest {
    enabled = false
  }
  node_to_node_encryption {
    enabled = false
  }
}

resource "aws_opensearch_domain" "os" {
  domain_name = "os"
}

resource "aws_redshift_cluster" "rs" {
  cluster_identifier  = "rs"
  publicly_accessible = true
}

resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
}

resource "aws_guardduty_detector" "gd" {
  enable = false
}

resource "aws_unrecognized_thing" "other" {
  ssh_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@example"
}

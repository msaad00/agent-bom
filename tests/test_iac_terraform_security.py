"""Tests for Terraform security misconfiguration scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.iac.terraform_security import scan_terraform_security


@pytest.fixture()
def tmp_tf(tmp_path: Path):
    """Helper to create a temporary .tf file."""

    def _write(content: str, name: str = "main.tf") -> Path:
        p = tmp_path / name
        p.write_text(content)
        return p

    return _write


class TestS3Encryption:
    """TF-SEC-001: S3 bucket without encryption."""

    def test_no_encryption(self, tmp_tf):
        content = """\
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "private"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf001 = [f for f in findings if f.rule_id == "TF-SEC-001"]
        assert len(tf001) == 1
        assert tf001[0].severity == "high"

    def test_with_encryption_ok(self, tmp_tf):
        content = """\
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf001 = [f for f in findings if f.rule_id == "TF-SEC-001"]
        assert len(tf001) == 0


class TestS3PublicACL:
    """TF-SEC-002: S3 bucket with public ACL."""

    def test_public_read(self, tmp_tf):
        content = """\
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl    = "public-read"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf002 = [f for f in findings if f.rule_id == "TF-SEC-002"]
        assert len(tf002) == 1
        assert tf002[0].severity == "critical"

    def test_private_acl_ok(self, tmp_tf):
        content = """\
resource "aws_s3_bucket" "private" {
  bucket = "my-private-bucket"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf002 = [f for f in findings if f.rule_id == "TF-SEC-002"]
        assert len(tf002) == 0


class TestSecurityGroupCIDR:
    """TF-SEC-003: Security group with 0.0.0.0/0 on non-web port."""

    def test_open_ssh(self, tmp_tf):
        content = """\
resource "aws_security_group" "allow_ssh" {
  name = "allow_ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf003 = [f for f in findings if f.rule_id == "TF-SEC-003"]
        assert len(tf003) == 1

    def test_open_http_ok(self, tmp_tf):
        content = """\
resource "aws_security_group" "allow_http" {
  name = "allow_http"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf003 = [f for f in findings if f.rule_id == "TF-SEC-003"]
        assert len(tf003) == 0

    def test_restricted_cidr_ok(self, tmp_tf):
        content = """\
resource "aws_security_group" "restricted" {
  name = "restricted"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf003 = [f for f in findings if f.rule_id == "TF-SEC-003"]
        assert len(tf003) == 0


class TestIAMWildcard:
    """TF-SEC-004: IAM policy with Action/Resource *."""

    def test_action_star(self, tmp_tf):
        content = """\
resource "aws_iam_policy" "admin" {
  name = "admin"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "arn:aws:s3:::my-bucket"
  }]
}
EOF
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf004 = [f for f in findings if f.rule_id == "TF-SEC-004"]
        assert len(tf004) >= 1

    def test_resource_star(self, tmp_tf):
        content = """\
resource "aws_iam_policy" "broad" {
  name = "broad"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*"
  }]
}
EOF
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf004 = [f for f in findings if f.rule_id == "TF-SEC-004"]
        assert len(tf004) >= 1

    def test_scoped_policy_ok(self, tmp_tf):
        content = """\
resource "aws_iam_policy" "scoped" {
  name = "scoped"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*"
  }]
}
EOF
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf004 = [f for f in findings if f.rule_id == "TF-SEC-004"]
        assert len(tf004) == 0


class TestRDSEncryption:
    """TF-SEC-005: RDS without encryption."""

    def test_encrypted_false(self, tmp_tf):
        content = """\
resource "aws_db_instance" "db" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  storage_encrypted = false
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf005 = [f for f in findings if f.rule_id == "TF-SEC-005"]
        assert len(tf005) >= 1

    def test_no_encryption_key(self, tmp_tf):
        content = """\
resource "aws_db_instance" "db" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf005 = [f for f in findings if f.rule_id == "TF-SEC-005"]
        assert len(tf005) >= 1

    def test_encrypted_true_ok(self, tmp_tf):
        content = """\
resource "aws_db_instance" "db" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  storage_encrypted = true
  enabled_cloudwatch_logs_exports = ["audit", "general"]
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf005 = [f for f in findings if f.rule_id == "TF-SEC-005"]
        assert len(tf005) == 0


class TestCloudWatchLogging:
    """TF-SEC-006: CloudWatch logging not enabled."""

    def test_no_logging(self, tmp_tf):
        content = """\
resource "aws_db_instance" "db" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  storage_encrypted = true
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf006 = [f for f in findings if f.rule_id == "TF-SEC-006"]
        assert len(tf006) >= 1

    def test_with_logging_ok(self, tmp_tf):
        content = """\
resource "aws_db_instance" "db" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  storage_encrypted = true
  enabled_cloudwatch_logs_exports = ["audit", "general"]
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf006 = [f for f in findings if f.rule_id == "TF-SEC-006"]
        assert len(tf006) == 0


class TestSSHKeyHardcoded:
    """TF-SEC-007: SSH key hardcoded."""

    def test_hardcoded_ssh_key(self, tmp_tf):
        content = """\
resource "aws_key_pair" "deployer" {
  key_name   = "deployer-key"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD..."
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf007 = [f for f in findings if f.rule_id == "TF-SEC-007"]
        assert len(tf007) == 1
        assert tf007[0].severity == "high"

    def test_file_reference_ok(self, tmp_tf):
        content = """\
resource "aws_key_pair" "deployer" {
  key_name   = "deployer-key"
  public_key = file("~/.ssh/id_rsa.pub")
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        tf007 = [f for f in findings if f.rule_id == "TF-SEC-007"]
        assert len(tf007) == 0


class TestS3Versioning:
    """TF-SEC-021: S3 bucket versioning not enabled."""

    def test_no_versioning(self, tmp_tf):
        content = """\
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-021"]
        assert len(hits) == 1
        assert hits[0].severity == "medium"

    def test_versioning_enabled_ok(self, tmp_tf):
        content = """\
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-021"]
        assert len(hits) == 0


class TestS3PublicAccessBlock:
    """TF-SEC-022: S3 bucket public access block missing."""

    def test_no_public_access_block(self, tmp_tf):
        content = """\
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-022"]
        assert len(hits) == 1
        assert hits[0].severity == "high"

    def test_with_public_access_block_ok(self, tmp_tf):
        content = """\
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id
  block_public_acls = true
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-022"]
        assert len(hits) == 0


class TestS3Logging:
    """TF-SEC-023: S3 bucket logging not enabled."""

    def test_no_logging(self, tmp_tf):
        content = """\
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-023"]
        assert len(hits) == 1
        assert hits[0].severity == "medium"

    def test_with_logging_ok(self, tmp_tf):
        content = """\
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"

  logging {
    target_bucket = "my-log-bucket"
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-023"]
        assert len(hits) == 0


class TestRDSPublicAccess:
    """TF-SEC-024: RDS public accessibility enabled."""

    def test_publicly_accessible(self, tmp_tf):
        content = """\
resource "aws_db_instance" "db" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  storage_encrypted = true
  publicly_accessible = true
  enabled_cloudwatch_logs_exports = ["audit"]
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-024"]
        assert len(hits) == 1
        assert hits[0].severity == "critical"

    def test_not_publicly_accessible_ok(self, tmp_tf):
        content = """\
resource "aws_db_instance" "db" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  storage_encrypted = true
  publicly_accessible = false
  enabled_cloudwatch_logs_exports = ["audit"]
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-024"]
        assert len(hits) == 0


class TestRDSBackupRetention:
    """TF-SEC-025: RDS backup retention period < 7 days."""

    def test_short_retention(self, tmp_tf):
        content = """\
resource "aws_db_instance" "db" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  storage_encrypted = true
  backup_retention_period = 3
  enabled_cloudwatch_logs_exports = ["audit"]
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-025"]
        assert len(hits) == 1

    def test_adequate_retention_ok(self, tmp_tf):
        content = """\
resource "aws_db_instance" "db" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  storage_encrypted = true
  backup_retention_period = 14
  enabled_cloudwatch_logs_exports = ["audit"]
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-025"]
        assert len(hits) == 0

    def test_no_retention_set(self, tmp_tf):
        content = """\
resource "aws_db_instance" "db" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  storage_encrypted = true
  enabled_cloudwatch_logs_exports = ["audit"]
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-025"]
        assert len(hits) == 1


class TestRDSMultiAZ:
    """TF-SEC-026: RDS multi-AZ not enabled."""

    def test_no_multi_az(self, tmp_tf):
        content = """\
resource "aws_db_instance" "db" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  storage_encrypted = true
  enabled_cloudwatch_logs_exports = ["audit"]
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-026"]
        assert len(hits) == 1

    def test_multi_az_ok(self, tmp_tf):
        content = """\
resource "aws_db_instance" "db" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  storage_encrypted = true
  multi_az = true
  enabled_cloudwatch_logs_exports = ["audit"]
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-026"]
        assert len(hits) == 0


class TestEBSVolumeEncryption:
    """TF-SEC-027: EBS volume not encrypted."""

    def test_no_encryption(self, tmp_tf):
        content = """\
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-027"]
        assert len(hits) == 1
        assert hits[0].severity == "high"

    def test_encrypted_ok(self, tmp_tf):
        content = """\
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-027"]
        assert len(hits) == 0


class TestEBSSnapshotEncryption:
    """TF-SEC-028: EBS snapshot not encrypted."""

    def test_no_encryption(self, tmp_tf):
        content = """\
resource "aws_ebs_snapshot" "snap" {
  volume_id = "vol-12345"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-028"]
        assert len(hits) == 1
        assert hits[0].severity == "high"


class TestLBAccessLogging:
    """TF-SEC-029: ALB/ELB access logging not enabled."""

    def test_no_access_logs(self, tmp_tf):
        content = """\
resource "aws_lb" "main" {
  name = "main-lb"
  internal = false
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-029"]
        assert len(hits) == 1

    def test_access_logs_enabled_ok(self, tmp_tf):
        content = """\
resource "aws_lb" "main" {
  name = "main-lb"
  internal = false
  enable_deletion_protection = true

  access_logs {
    bucket  = "my-lb-logs"
    enabled = true
  }
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-029"]
        assert len(hits) == 0


class TestLBDeletionProtection:
    """TF-SEC-030: ALB/NLB deletion protection disabled."""

    def test_no_deletion_protection(self, tmp_tf):
        content = """\
resource "aws_lb" "main" {
  name = "main-lb"
  internal = false
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-030"]
        assert len(hits) == 1

    def test_deletion_protection_ok(self, tmp_tf):
        content = """\
resource "aws_lb" "main" {
  name = "main-lb"
  internal = false
  enable_deletion_protection = true

  access_logs {
    bucket  = "my-lb-logs"
    enabled = true
  }
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-030"]
        assert len(hits) == 0


class TestCloudTrailMultiRegion:
    """TF-SEC-031: CloudTrail not enabled for all regions."""

    def test_no_multi_region(self, tmp_tf):
        content = """\
resource "aws_cloudtrail" "main" {
  name           = "main-trail"
  s3_bucket_name = "my-bucket"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-031"]
        assert len(hits) == 1
        assert hits[0].severity == "high"

    def test_multi_region_ok(self, tmp_tf):
        content = """\
resource "aws_cloudtrail" "main" {
  name                  = "main-trail"
  s3_bucket_name        = "my-bucket"
  is_multi_region_trail = true
  enable_log_file_validation = true
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-031"]
        assert len(hits) == 0


class TestCloudTrailLogValidation:
    """TF-SEC-032: CloudTrail log file validation disabled."""

    def test_no_validation(self, tmp_tf):
        content = """\
resource "aws_cloudtrail" "main" {
  name           = "main-trail"
  s3_bucket_name = "my-bucket"
  is_multi_region_trail = true
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-032"]
        assert len(hits) == 1

    def test_validation_ok(self, tmp_tf):
        content = """\
resource "aws_cloudtrail" "main" {
  name                       = "main-trail"
  s3_bucket_name             = "my-bucket"
  is_multi_region_trail      = true
  enable_log_file_validation = true
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-032"]
        assert len(hits) == 0


class TestSNSEncryption:
    """TF-SEC-033: SNS topic not encrypted."""

    def test_no_encryption(self, tmp_tf):
        content = """\
resource "aws_sns_topic" "alerts" {
  name = "alerts"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-033"]
        assert len(hits) == 1

    def test_encrypted_ok(self, tmp_tf):
        content = """\
resource "aws_sns_topic" "alerts" {
  name              = "alerts"
  kms_master_key_id = "alias/my-key"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-033"]
        assert len(hits) == 0


class TestSQSEncryption:
    """TF-SEC-034: SQS queue not encrypted."""

    def test_no_encryption(self, tmp_tf):
        content = """\
resource "aws_sqs_queue" "jobs" {
  name = "jobs"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-034"]
        assert len(hits) == 1

    def test_encrypted_ok(self, tmp_tf):
        content = """\
resource "aws_sqs_queue" "jobs" {
  name              = "jobs"
  kms_master_key_id = "alias/my-key"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-034"]
        assert len(hits) == 0


class TestECRScanOnPush:
    """TF-SEC-035: ECR repository scan on push disabled."""

    def test_no_scan(self, tmp_tf):
        content = """\
resource "aws_ecr_repository" "app" {
  name = "app"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-035"]
        assert len(hits) == 1

    def test_scan_enabled_ok(self, tmp_tf):
        content = """\
resource "aws_ecr_repository" "app" {
  name = "app"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-035"]
        assert len(hits) == 0


class TestECRTagMutability:
    """TF-SEC-036: ECR repository image tag mutability enabled."""

    def test_mutable_tags(self, tmp_tf):
        content = """\
resource "aws_ecr_repository" "app" {
  name = "app"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-036"]
        assert len(hits) == 1

    def test_immutable_ok(self, tmp_tf):
        content = """\
resource "aws_ecr_repository" "app" {
  name                 = "app"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-036"]
        assert len(hits) == 0


class TestECSHostNetworking:
    """TF-SEC-037: ECS task definition with host networking."""

    def test_host_networking(self, tmp_tf):
        content = """\
resource "aws_ecs_task_definition" "app" {
  family       = "app"
  network_mode = "host"
  user         = "1000"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-037"]
        assert len(hits) == 1
        assert hits[0].severity == "high"

    def test_awsvpc_ok(self, tmp_tf):
        content = """\
resource "aws_ecs_task_definition" "app" {
  family       = "app"
  network_mode = "awsvpc"
  user         = "1000"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-037"]
        assert len(hits) == 0


class TestECSRunAsRoot:
    """TF-SEC-038: ECS task definition running as root."""

    def test_no_user(self, tmp_tf):
        content = """\
resource "aws_ecs_task_definition" "app" {
  family       = "app"
  network_mode = "awsvpc"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-038"]
        assert len(hits) == 1

    def test_nonroot_user_ok(self, tmp_tf):
        content = """\
resource "aws_ecs_task_definition" "app" {
  family       = "app"
  network_mode = "awsvpc"
  user         = "1000"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-038"]
        assert len(hits) == 0


class TestSecretsManagerKMS:
    """TF-SEC-039: Secrets Manager secret without KMS encryption."""

    def test_no_kms(self, tmp_tf):
        content = """\
resource "aws_secretsmanager_secret" "db_pass" {
  name = "db-password"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-039"]
        assert len(hits) == 1

    def test_with_kms_ok(self, tmp_tf):
        content = """\
resource "aws_secretsmanager_secret" "db_pass" {
  name       = "db-password"
  kms_key_id = "arn:aws:kms:us-east-1:123456789:key/abc"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-039"]
        assert len(hits) == 0


class TestSSMSecureString:
    """TF-SEC-040: SSM Parameter SecureString without CMK."""

    def test_securestring_no_key(self, tmp_tf):
        content = """\
resource "aws_ssm_parameter" "secret" {
  name  = "/app/secret"
  type  = "SecureString"
  value = "supersecret"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-040"]
        assert len(hits) == 1

    def test_securestring_with_key_ok(self, tmp_tf):
        content = """\
resource "aws_ssm_parameter" "secret" {
  name   = "/app/secret"
  type   = "SecureString"
  value  = "supersecret"
  key_id = "alias/my-key"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-040"]
        assert len(hits) == 0


class TestDefaultSecurityGroup:
    """TF-SEC-041: VPC default security group allows traffic."""

    def test_default_sg_with_rules(self, tmp_tf):
        content = """\
resource "aws_default_security_group" "default" {
  vpc_id = "vpc-123"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-041"]
        assert len(hits) == 1
        assert hits[0].severity == "high"

    def test_default_sg_empty_ok(self, tmp_tf):
        content = """\
resource "aws_default_security_group" "default" {
  vpc_id = "vpc-123"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-041"]
        assert len(hits) == 0


class TestRDSDeletionProtection:
    """TF-SEC-042: RDS instance without deletion protection."""

    def test_no_deletion_protection(self, tmp_tf):
        content = """\
resource "aws_db_instance" "db" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  storage_encrypted = true
  enabled_cloudwatch_logs_exports = ["audit"]
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-042"]
        assert len(hits) == 1

    def test_deletion_protection_ok(self, tmp_tf):
        content = """\
resource "aws_db_instance" "db" {
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  storage_encrypted   = true
  deletion_protection = true
  enabled_cloudwatch_logs_exports = ["audit"]
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-042"]
        assert len(hits) == 0


class TestElasticsearchEncryptAtRest:
    """TF-SEC-043: Elasticsearch/OpenSearch without encryption at rest."""

    def test_no_encryption(self, tmp_tf):
        content = """\
resource "aws_elasticsearch_domain" "es" {
  domain_name = "my-domain"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-043"]
        assert len(hits) == 1

    def test_encrypted_ok(self, tmp_tf):
        content = """\
resource "aws_elasticsearch_domain" "es" {
  domain_name = "my-domain"

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }

  logging {
    enabled = true
  }
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-043"]
        assert len(hits) == 0


class TestElasticsearchNodeToNode:
    """TF-SEC-044: Elasticsearch/OpenSearch without node-to-node encryption."""

    def test_no_n2n(self, tmp_tf):
        content = """\
resource "aws_opensearch_domain" "os" {
  domain_name = "my-domain"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-044"]
        assert len(hits) == 1

    def test_n2n_ok(self, tmp_tf):
        content = """\
resource "aws_opensearch_domain" "os" {
  domain_name = "my-domain"

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-044"]
        assert len(hits) == 0


class TestLambdaVPC:
    """TF-SEC-045: Lambda function without VPC configuration."""

    def test_no_vpc(self, tmp_tf):
        content = """\
resource "aws_lambda_function" "fn" {
  function_name = "my-fn"
  handler       = "index.handler"
  runtime       = "python3.12"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-045"]
        assert len(hits) == 1
        assert hits[0].severity == "low"

    def test_with_vpc_ok(self, tmp_tf):
        content = """\
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
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-045"]
        assert len(hits) == 0


class TestLambdaSensitiveEnv:
    """TF-SEC-046: Lambda environment variables with sensitive values."""

    def test_sensitive_env_var(self, tmp_tf):
        content = """\
resource "aws_lambda_function" "fn" {
  function_name = "my-fn"
  handler       = "index.handler"
  runtime       = "python3.12"

  environment {
    variables = {
      API_KEY = "sk-1234567890abcdef"
    }
  }
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-046"]
        assert len(hits) == 1
        assert hits[0].severity == "critical"

    def test_safe_env_ok(self, tmp_tf):
        content = """\
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
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-046"]
        assert len(hits) == 0


class TestRedshiftEncryption:
    """TF-SEC-047: Redshift cluster without encryption."""

    def test_no_encryption(self, tmp_tf):
        content = """\
resource "aws_redshift_cluster" "dw" {
  cluster_identifier = "my-dw"
  node_type          = "dc2.large"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-047"]
        assert len(hits) == 1
        assert hits[0].severity == "high"

    def test_encrypted_ok(self, tmp_tf):
        content = """\
resource "aws_redshift_cluster" "dw" {
  cluster_identifier  = "my-dw"
  node_type           = "dc2.large"
  encrypted           = true
  publicly_accessible = false
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-047"]
        assert len(hits) == 0


class TestRedshiftPublicAccess:
    """TF-SEC-048: Redshift cluster publicly accessible."""

    def test_public_access(self, tmp_tf):
        content = """\
resource "aws_redshift_cluster" "dw" {
  cluster_identifier  = "my-dw"
  node_type           = "dc2.large"
  encrypted           = true
  publicly_accessible = true
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-048"]
        assert len(hits) == 1
        assert hits[0].severity == "critical"

    def test_not_public_ok(self, tmp_tf):
        content = """\
resource "aws_redshift_cluster" "dw" {
  cluster_identifier  = "my-dw"
  node_type           = "dc2.large"
  encrypted           = true
  publicly_accessible = false
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-048"]
        assert len(hits) == 0


class TestWAFAssociation:
    """TF-SEC-049: WAF not associated with ALB/CloudFront."""

    def test_no_waf(self, tmp_tf):
        content = """\
resource "aws_lb" "main" {
  name     = "main-lb"
  internal = false
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-049"]
        assert len(hits) == 1

    def test_with_waf_ok(self, tmp_tf):
        content = """\
resource "aws_lb" "main" {
  name     = "main-lb"
  internal = false
}

resource "aws_wafv2_web_acl_association" "main" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = "arn:aws:wafv2:us-east-1:123:regional/webacl/example/abc"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-049"]
        assert len(hits) == 0


class TestGuardDuty:
    """TF-SEC-050: GuardDuty not enabled."""

    def test_guardduty_disabled(self, tmp_tf):
        content = """\
resource "aws_guardduty_detector" "main" {
  enable = false
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-050"]
        assert len(hits) == 1
        assert hits[0].severity == "high"

    def test_guardduty_enabled_ok(self, tmp_tf):
        content = """\
resource "aws_guardduty_detector" "main" {
  enable = true
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        hits = [f for f in findings if f.rule_id == "TF-SEC-050"]
        assert len(hits) == 0


class TestTerraformCompliance:
    """All findings have compliance tags."""

    def test_compliance_tags(self, tmp_tf):
        content = """\
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
  acl    = "public-read"
}
"""
        findings = scan_terraform_security(tmp_tf(content))
        for f in findings:
            assert len(f.compliance) > 0, f"Finding {f.rule_id} has no compliance tags"
            assert f.category == "terraform"


class TestNonTfFile:
    """Scanner ignores non-.tf files."""

    def test_non_tf_ignored(self, tmp_path):
        p = tmp_path / "main.py"
        p.write_text('acl = "public-read"')
        findings = scan_terraform_security(p)
        assert len(findings) == 0

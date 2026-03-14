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

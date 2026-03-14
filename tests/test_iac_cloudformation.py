"""Tests for CloudFormation security misconfiguration scanner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.iac.cloudformation import scan_cloudformation


@pytest.fixture()
def cfn_json(tmp_path: Path):
    """Helper to create a temporary CloudFormation JSON template."""

    def _write(template: dict, name: str = "template.json") -> Path:
        p = tmp_path / name
        p.write_text(json.dumps(template, indent=2))
        return p

    return _write


@pytest.fixture()
def cfn_yaml(tmp_path: Path):
    """Helper to create a temporary CloudFormation YAML template."""

    def _write(content: str, name: str = "template.yaml") -> Path:
        p = tmp_path / name
        p.write_text(content)
        return p

    return _write


def _base_template(**resources) -> dict:
    """Build a minimal CloudFormation template with given resources."""
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
    }


# ── CFN-001: S3 bucket without encryption ────────────────────────────────────


class TestCFN001S3Encryption:
    """CFN-001: S3 bucket without BucketEncryption (AWS SEC08, CIS 2.1.1)."""

    def test_no_encryption(self, cfn_json):
        template = _base_template(
            DataBucket={
                "Type": "AWS::S3::Bucket",
                "Properties": {"BucketName": "my-data-bucket"},
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn001 = [f for f in findings if f.rule_id == "CFN-001"]
        assert len(cfn001) == 1
        assert cfn001[0].severity == "high"
        assert "CIS-AWS-2.1.1" in cfn001[0].compliance

    def test_with_encryption_ok(self, cfn_json):
        template = _base_template(
            DataBucket={
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": "my-data-bucket",
                    "BucketEncryption": {
                        "ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
                    },
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn001 = [f for f in findings if f.rule_id == "CFN-001"]
        assert len(cfn001) == 0


# ── CFN-002: S3 bucket with public ACL ───────────────────────────────────────


class TestCFN002S3PublicACL:
    """CFN-002: S3 bucket with public ACL (AWS SEC01, CIS 2.1.2)."""

    def test_public_read(self, cfn_json):
        template = _base_template(
            PublicBucket={
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "AccessControl": "PublicRead",
                    "BucketEncryption": {
                        "ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                    },
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn002 = [f for f in findings if f.rule_id == "CFN-002"]
        assert len(cfn002) == 1
        assert cfn002[0].severity == "critical"

    def test_public_read_write(self, cfn_json):
        template = _base_template(
            PublicBucket={
                "Type": "AWS::S3::Bucket",
                "Properties": {"AccessControl": "PublicReadWrite"},
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn002 = [f for f in findings if f.rule_id == "CFN-002"]
        assert len(cfn002) == 1

    def test_private_acl_ok(self, cfn_json):
        template = _base_template(
            PrivateBucket={
                "Type": "AWS::S3::Bucket",
                "Properties": {"AccessControl": "Private"},
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn002 = [f for f in findings if f.rule_id == "CFN-002"]
        assert len(cfn002) == 0


# ── CFN-003: Security group open to 0.0.0.0/0 ───────────────────────────────


class TestCFN003SecurityGroup:
    """CFN-003: Security group with 0.0.0.0/0 on non-standard ports (CIS 5.2)."""

    def test_open_ssh(self, cfn_json):
        template = _base_template(
            AllowSSH={
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "Allow SSH",
                    "SecurityGroupIngress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "CidrIp": "0.0.0.0/0",
                        }
                    ],
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn003 = [f for f in findings if f.rule_id == "CFN-003"]
        assert len(cfn003) == 1
        assert cfn003[0].severity == "high"

    def test_open_ipv6(self, cfn_json):
        template = _base_template(
            AllowSSHv6={
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "Allow SSH IPv6",
                    "SecurityGroupIngress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "CidrIpv6": "::/0",
                        }
                    ],
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn003 = [f for f in findings if f.rule_id == "CFN-003"]
        assert len(cfn003) == 1

    def test_open_https_ok(self, cfn_json):
        template = _base_template(
            AllowHTTPS={
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "Allow HTTPS",
                    "SecurityGroupIngress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "CidrIp": "0.0.0.0/0",
                        }
                    ],
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn003 = [f for f in findings if f.rule_id == "CFN-003"]
        assert len(cfn003) == 0

    def test_restricted_cidr_ok(self, cfn_json):
        template = _base_template(
            RestrictedSSH={
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "Restricted SSH",
                    "SecurityGroupIngress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "CidrIp": "10.0.0.0/8",
                        }
                    ],
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn003 = [f for f in findings if f.rule_id == "CFN-003"]
        assert len(cfn003) == 0


# ── CFN-004: IAM policy with wildcard ────────────────────────────────────────


class TestCFN004IAMWildcard:
    """CFN-004: IAM policy with Action: * or Resource: * (AWS SEC03, CIS 1.16)."""

    def test_action_star(self, cfn_json):
        template = _base_template(
            AdminPolicy={
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyName": "admin",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket"}],
                    },
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn004 = [f for f in findings if f.rule_id == "CFN-004"]
        assert len(cfn004) == 1
        assert cfn004[0].severity == "high"

    def test_resource_star(self, cfn_json):
        template = _base_template(
            BroadPolicy={
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyName": "broad",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
                    },
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn004 = [f for f in findings if f.rule_id == "CFN-004"]
        assert len(cfn004) == 1

    def test_role_with_inline_policy(self, cfn_json):
        template = _base_template(
            AdminRole={
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "Policies": [
                        {
                            "PolicyName": "admin-inline",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                            },
                        }
                    ],
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn004 = [f for f in findings if f.rule_id == "CFN-004"]
        assert len(cfn004) >= 1

    def test_scoped_policy_ok(self, cfn_json):
        template = _base_template(
            ScopedPolicy={
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyName": "scoped",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "arn:aws:s3:::my-bucket/*",
                            }
                        ],
                    },
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn004 = [f for f in findings if f.rule_id == "CFN-004"]
        assert len(cfn004) == 0


# ── CFN-005: RDS without encryption ──────────────────────────────────────────


class TestCFN005RDSEncryption:
    """CFN-005: RDS instance without StorageEncrypted (CIS 2.3.1)."""

    def test_no_encryption(self, cfn_json):
        template = _base_template(
            MyDB={
                "Type": "AWS::RDS::DBInstance",
                "Properties": {"Engine": "mysql", "DBInstanceClass": "db.t3.micro"},
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn005 = [f for f in findings if f.rule_id == "CFN-005"]
        assert len(cfn005) == 1
        assert cfn005[0].severity == "high"

    def test_encrypted_true_ok(self, cfn_json):
        template = _base_template(
            MyDB={
                "Type": "AWS::RDS::DBInstance",
                "Properties": {
                    "Engine": "mysql",
                    "DBInstanceClass": "db.t3.micro",
                    "StorageEncrypted": True,
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn005 = [f for f in findings if f.rule_id == "CFN-005"]
        assert len(cfn005) == 0


# ── CFN-006: EC2 without IAM profile ────────────────────────────────────────


class TestCFN006EC2NoIAMProfile:
    """CFN-006: EC2 instance without IamInstanceProfile (CIS 1.14)."""

    def test_no_iam_profile(self, cfn_json):
        template = _base_template(
            WebServer={
                "Type": "AWS::EC2::Instance",
                "Properties": {"ImageId": "ami-12345678", "InstanceType": "t3.micro"},
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn006 = [f for f in findings if f.rule_id == "CFN-006"]
        assert len(cfn006) == 1
        assert cfn006[0].severity == "medium"

    def test_with_iam_profile_ok(self, cfn_json):
        template = _base_template(
            WebServer={
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "ImageId": "ami-12345678",
                    "InstanceType": "t3.micro",
                    "IamInstanceProfile": {"Ref": "MyInstanceProfile"},
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn006 = [f for f in findings if f.rule_id == "CFN-006"]
        assert len(cfn006) == 0


# ── CFN-007: Hardcoded secrets in Parameters ────────────────────────────────


class TestCFN007HardcodedSecrets:
    """CFN-007: Hardcoded secret in parameter default (AWS SEC02, CIS 1.4)."""

    def test_api_key_default(self, cfn_json):
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "ApiKey": {
                    "Type": "String",
                    "Default": "sk-1234567890abcdef",
                }
            },
            "Resources": {},
        }
        findings = scan_cloudformation(cfn_json(template))
        cfn007 = [f for f in findings if f.rule_id == "CFN-007"]
        assert len(cfn007) == 1
        assert cfn007[0].severity == "critical"

    def test_password_default(self, cfn_json):
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "DBPassword": {
                    "Type": "String",
                    "Default": "supersecret123",
                }
            },
            "Resources": {},
        }
        findings = scan_cloudformation(cfn_json(template))
        cfn007 = [f for f in findings if f.rule_id == "CFN-007"]
        assert len(cfn007) == 1

    def test_placeholder_ok(self, cfn_json):
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "ApiKey": {
                    "Type": "String",
                    "Default": "CHANGE_ME",
                }
            },
            "Resources": {},
        }
        findings = scan_cloudformation(cfn_json(template))
        cfn007 = [f for f in findings if f.rule_id == "CFN-007"]
        assert len(cfn007) == 0

    def test_no_default_ok(self, cfn_json):
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "ApiKey": {"Type": "String"},
            },
            "Resources": {},
        }
        findings = scan_cloudformation(cfn_json(template))
        cfn007 = [f for f in findings if f.rule_id == "CFN-007"]
        assert len(cfn007) == 0


# ── CFN-008: CloudTrail not multi-region ─────────────────────────────────────


class TestCFN008CloudTrail:
    """CFN-008: CloudTrail not multi-region (AWS SEC04, CIS 3.1)."""

    def test_not_multi_region(self, cfn_json):
        template = _base_template(
            Trail={
                "Type": "AWS::CloudTrail::Trail",
                "Properties": {
                    "TrailName": "my-trail",
                    "S3BucketName": "trail-bucket",
                    "IsLogging": True,
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn008 = [f for f in findings if f.rule_id == "CFN-008"]
        assert len(cfn008) == 1
        assert cfn008[0].severity == "medium"

    def test_multi_region_ok(self, cfn_json):
        template = _base_template(
            Trail={
                "Type": "AWS::CloudTrail::Trail",
                "Properties": {
                    "TrailName": "my-trail",
                    "S3BucketName": "trail-bucket",
                    "IsLogging": True,
                    "IsMultiRegionTrail": True,
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn008 = [f for f in findings if f.rule_id == "CFN-008"]
        assert len(cfn008) == 0


# ── CFN-009: EBS volume not encrypted ────────────────────────────────────────


class TestCFN009EBSEncryption:
    """CFN-009: EBS volume not encrypted (CIS 2.2.1)."""

    def test_not_encrypted(self, cfn_json):
        template = _base_template(
            DataVolume={
                "Type": "AWS::EC2::Volume",
                "Properties": {"AvailabilityZone": "us-east-1a", "Size": 100},
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn009 = [f for f in findings if f.rule_id == "CFN-009"]
        assert len(cfn009) == 1
        assert cfn009[0].severity == "high"

    def test_encrypted_ok(self, cfn_json):
        template = _base_template(
            DataVolume={
                "Type": "AWS::EC2::Volume",
                "Properties": {
                    "AvailabilityZone": "us-east-1a",
                    "Size": 100,
                    "Encrypted": True,
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn009 = [f for f in findings if f.rule_id == "CFN-009"]
        assert len(cfn009) == 0


# ── CFN-010: Lambda without VPC config ───────────────────────────────────────


class TestCFN010LambdaVPC:
    """CFN-010: Lambda function without VPC configuration (AWS SEC05)."""

    def test_no_vpc(self, cfn_json):
        template = _base_template(
            MyFunction={
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": "my-func",
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Code": {"ZipFile": "def handler(event, context): pass"},
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn010 = [f for f in findings if f.rule_id == "CFN-010"]
        assert len(cfn010) == 1
        assert cfn010[0].severity == "medium"

    def test_with_vpc_ok(self, cfn_json):
        template = _base_template(
            MyFunction={
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": "my-func",
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Code": {"ZipFile": "def handler(event, context): pass"},
                    "VpcConfig": {
                        "SubnetIds": ["subnet-12345"],
                        "SecurityGroupIds": ["sg-12345"],
                    },
                },
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn010 = [f for f in findings if f.rule_id == "CFN-010"]
        assert len(cfn010) == 0


# ── YAML support ─────────────────────────────────────────────────────────────


class TestCFNYAMLSupport:
    """CloudFormation YAML templates are scanned correctly."""

    def test_yaml_template(self, cfn_yaml):
        content = """\
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-data-bucket
"""
        findings = scan_cloudformation(cfn_yaml(content))
        cfn001 = [f for f in findings if f.rule_id == "CFN-001"]
        assert len(cfn001) == 1


# ── Compliance tags ──────────────────────────────────────────────────────────


class TestCFNComplianceTags:
    """All findings have compliance tags and correct category."""

    def test_compliance_tags(self, cfn_json):
        template = _base_template(
            DataBucket={
                "Type": "AWS::S3::Bucket",
                "Properties": {"AccessControl": "PublicRead"},
            }
        )
        findings = scan_cloudformation(cfn_json(template))
        for f in findings:
            assert len(f.compliance) > 0, f"Finding {f.rule_id} has no compliance tags"
            assert f.category == "cloudformation"


# ── Edge cases ───────────────────────────────────────────────────────────────


class TestCFNEdgeCases:
    """Edge cases: non-CFN files, empty templates, invalid JSON."""

    def test_non_cfn_ignored(self, tmp_path):
        p = tmp_path / "main.py"
        p.write_text('Resources = {"foo": "bar"}')
        findings = scan_cloudformation(p)
        assert len(findings) == 0

    def test_empty_resources(self, cfn_json):
        template = {"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}}
        findings = scan_cloudformation(cfn_json(template))
        assert len(findings) == 0

    def test_invalid_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not valid json")
        findings = scan_cloudformation(p)
        assert len(findings) == 0

    def test_multiple_resources(self, cfn_json):
        """Multiple resources should each be individually checked."""
        template = _base_template(
            Bucket1={
                "Type": "AWS::S3::Bucket",
                "Properties": {"BucketName": "bucket1"},
            },
            Bucket2={
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": "bucket2",
                    "BucketEncryption": {
                        "ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                    },
                },
            },
        )
        findings = scan_cloudformation(cfn_json(template))
        cfn001 = [f for f in findings if f.rule_id == "CFN-001"]
        # Only Bucket1 should trigger CFN-001 (no encryption)
        assert len(cfn001) == 1
        assert "Bucket1" in cfn001[0].message

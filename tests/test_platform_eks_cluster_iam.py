"""Managed-node bootstrap uses role-scoped IAM without weakening encryption."""

import re

from tests.test_platform_eks_secret_wiring import MAIN, README, _balanced_hcl_block


def test_managed_nodes_do_not_request_auto_mode_or_standalone_encryption_policies():
    cluster = _balanced_hcl_block(MAIN, 'module "eks"')
    assert re.search(r"enable_auto_mode_custom_tags\s*=\s*false", cluster)
    assert re.search(r"attach_cluster_encryption_policy\s*=\s*false", cluster)
    # Keep the module's customer-managed KMS key and secrets encryption enabled.
    assert not re.search(r"create_kms_key\s*=\s*false|cluster_encryption_config\s*=\s*\{\s*\}", cluster)


def test_inline_encryption_policy_retains_exact_key_and_existing_permission_set():
    policy = _balanced_hcl_block(MAIN, 'resource "aws_iam_role_policy" "cluster_encryption"')
    assert re.search(r"count\s*=\s*var.create_cluster\s*\?\s*1\s*:\s*0", policy)
    assert re.search(r"role\s*=\s*module.eks\[0\].cluster_iam_role_name", policy)
    assert re.search(r"Resource\s*=\s*module.eks\[0\].kms_key_arn", policy)
    assert set(re.findall(r'"(kms:[A-Za-z*]+)"', policy)) == {"kms:Encrypt", "kms:Decrypt", "kms:ListGrants", "kms:DescribeKey"}
    assert '"*"' not in policy
    assert "-target=aws_iam_role_policy.cluster_encryption" in README
    assert "iam:PutRolePolicy" in README

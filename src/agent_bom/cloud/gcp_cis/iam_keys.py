"""CIS GCP 1.9-1.15: KMS key access/rotation, API keys and essential contacts."""

from __future__ import annotations

import logging

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.normalization import sanitize_discovery_warning

from ._base import (
    _IAM_SECTION,
    _gcp_kms_crypto_keys,
    _seams,
)

logger = logging.getLogger("agent_bom.cloud.gcp_cis_benchmark")


def _check_1_9(project_id: str) -> CISCheckResult:
    """CIS 1.9 — Ensure Cloud KMS encryption keys are not anonymously or publicly accessible."""
    result = CISCheckResult(
        check_id="1.9",
        title="Cloud KMS keys not publicly accessible",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation="Remove allUsers and allAuthenticatedUsers from Cloud KMS key IAM policies.",
        cis_section=_IAM_SECTION,
    )
    try:
        kms = _seams()._discovery_client("cloudkms", "v1")
        public_keys: list[str] = []

        for key in _gcp_kms_crypto_keys(project_id):
            key_name = key.get("name", "")
            if not key_name:
                continue
            policy = kms.projects().locations().keyRings().cryptoKeys().getIamPolicy(resource=key_name).execute()
            for binding in policy.get("bindings", []):
                members = binding.get("members", [])
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    public_keys.append(key_name)

        if public_keys:
            result.status = CheckStatus.FAIL
            result.evidence = f"Publicly accessible KMS keys: {', '.join(public_keys[:10])}"
            result.resource_ids = public_keys
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No KMS encryption keys are anonymously or publicly accessible."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check KMS key IAM policies: {sanitize_discovery_warning(exc)}"
    return result


def _check_1_10(project_id: str) -> CISCheckResult:
    """CIS 1.10 — Ensure KMS encryption keys are rotated within a period of 90 days."""
    result = CISCheckResult(
        check_id="1.10",
        title="KMS keys rotated within 90 days",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set a rotation period of 90 days or less on all Cloud KMS encryption keys.",
        cis_section=_IAM_SECTION,
    )
    try:
        failing: list[str] = []
        max_rotation_seconds = 90 * 24 * 60 * 60  # 90 days in seconds

        for key in _gcp_kms_crypto_keys(project_id):
            key_name = key.get("name", "")
            rotation_period = key.get("rotationPeriod", "")
            if not rotation_period:
                failing.append(key_name)
            else:
                # rotationPeriod is like "7776000s"
                period_s = int(rotation_period.rstrip("s"))
                if period_s > max_rotation_seconds:
                    failing.append(key_name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"KMS keys without 90-day rotation: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "All KMS encryption keys have rotation periods within 90 days."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check KMS key rotation: {sanitize_discovery_warning(exc)}"
    return result


def _check_1_11(project_id: str) -> CISCheckResult:
    """CIS 1.11 — Ensure separation of duties is enforced while assigning KMS-related roles."""
    result = CISCheckResult(
        check_id="1.11",
        title="Separation of duties for KMS role assignment",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Ensure no user has both cloudkms.admin and any of cloudkms.cryptoKeyEncrypterDecrypter, cloudkms.cryptoKeyEncrypter, or cloudkms.cryptoKeyDecrypter roles.",  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        cis_section=_IAM_SECTION,
    )
    try:
        crm = _seams()._discovery_client("cloudresourcemanager", "v1")
        policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
        bindings = policy.get("bindings", [])

        admin_role = "roles/cloudkms.admin"
        crypto_roles = {
            "roles/cloudkms.cryptoKeyEncrypterDecrypter",
            "roles/cloudkms.cryptoKeyEncrypter",
            "roles/cloudkms.cryptoKeyDecrypter",
        }

        admins: set[str] = set()
        crypto_members: set[str] = set()

        for binding in bindings:
            role = binding.get("role", "")
            members = binding.get("members", [])
            if role == admin_role:
                admins.update(members)
            elif role in crypto_roles:
                crypto_members.update(members)

        overlap = admins & crypto_members
        if overlap:
            failing = list(overlap)
            result.status = CheckStatus.FAIL
            result.evidence = f"Members with both KMS admin and crypto roles: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No members have both KMS admin and crypto encrypter/decrypter roles."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check KMS role separation: {sanitize_discovery_warning(exc)}"
    return result


def _check_1_12(project_id: str) -> CISCheckResult:
    """CIS 1.12 — Ensure API keys are restricted to only APIs the application needs."""
    result = CISCheckResult(
        check_id="1.12",
        title="API keys restricted to needed APIs",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Restrict each API key to only the specific APIs required by the application.",
        cis_section=_IAM_SECTION,
    )
    try:
        apikeys = _seams()._discovery_client("apikeys", "v2")
        keys_resp = apikeys.projects().locations().keys().list(parent=f"projects/{project_id}/locations/global").execute()
        keys = keys_resp.get("keys", [])

        unrestricted: list[str] = []
        for key in keys:
            key_name = key.get("name", "")
            # Get full key details
            key_detail = apikeys.projects().locations().keys().get(name=key_name).execute()
            restrictions = key_detail.get("restrictions", {})
            api_targets = restrictions.get("apiTargets", [])
            if not api_targets:
                unrestricted.append(key.get("displayName", key_name))

        if unrestricted:
            result.status = CheckStatus.FAIL
            result.evidence = f"API keys without API restrictions: {', '.join(unrestricted[:10])}"
            result.resource_ids = unrestricted
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(keys)} API key(s) are restricted to specific APIs."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check API key restrictions: {sanitize_discovery_warning(exc)}"
    return result


def _check_1_13(project_id: str) -> CISCheckResult:
    """CIS 1.13 — Ensure API keys are restricted to specific hosts and apps."""
    result = CISCheckResult(
        check_id="1.13",
        title="API keys restricted to specific hosts and apps",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Add application restrictions (HTTP referrers, IP addresses, Android/iOS apps) to each API key.",
        cis_section=_IAM_SECTION,
    )
    try:
        apikeys = _seams()._discovery_client("apikeys", "v2")
        keys_resp = apikeys.projects().locations().keys().list(parent=f"projects/{project_id}/locations/global").execute()
        keys = keys_resp.get("keys", [])

        unrestricted: list[str] = []
        for key in keys:
            key_name = key.get("name", "")
            key_detail = apikeys.projects().locations().keys().get(name=key_name).execute()
            restrictions = key_detail.get("restrictions", {})
            has_app_restriction = any(
                restrictions.get(r)
                for r in ("browserKeyRestrictions", "serverKeyRestrictions", "androidKeyRestrictions", "iosKeyRestrictions")
            )
            if not has_app_restriction:
                unrestricted.append(key.get("displayName", key_name))

        if unrestricted:
            result.status = CheckStatus.FAIL
            result.evidence = f"API keys without host/app restrictions: {', '.join(unrestricted[:10])}"
            result.resource_ids = unrestricted
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(keys)} API key(s) are restricted to specific hosts or apps."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check API key host/app restrictions: {sanitize_discovery_warning(exc)}"
    return result


def _check_1_14(project_id: str) -> CISCheckResult:
    """CIS 1.14 — Ensure API keys are rotated within 90 days."""
    result = CISCheckResult(
        check_id="1.14",
        title="API keys rotated within 90 days",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Rotate API keys every 90 days or less to reduce the impact of compromised keys.",
        cis_section=_IAM_SECTION,
    )
    try:
        import datetime

        apikeys = _seams()._discovery_client("apikeys", "v2")
        keys_resp = apikeys.projects().locations().keys().list(parent=f"projects/{project_id}/locations/global").execute()
        keys = keys_resp.get("keys", [])

        failing: list[str] = []
        now = datetime.datetime.now(datetime.timezone.utc)
        threshold = datetime.timedelta(days=90)

        for key in keys:
            create_time = key.get("createTime", "")
            if create_time:
                created_dt = datetime.datetime.fromisoformat(create_time.replace("Z", "+00:00"))
                if now - created_dt > threshold:
                    failing.append(key.get("displayName", key.get("name", "unknown")))

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"API keys older than 90 days: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(keys)} API key(s) are within 90-day rotation."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check API key rotation: {sanitize_discovery_warning(exc)}"
    return result


def _check_1_15(project_id: str) -> CISCheckResult:
    """CIS 1.15 — Ensure essential contacts is configured for the organization."""
    result = CISCheckResult(
        check_id="1.15",
        title="Essential contacts configured for the org",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Configure Essential Contacts for SECURITY, TECHNICAL, and BILLING notification categories.",
        cis_section=_IAM_SECTION,
    )
    try:
        essentialcontacts = _seams()._discovery_client("essentialcontacts", "v1")
        contacts = essentialcontacts.projects().contacts().list(parent=f"projects/{project_id}").execute()
        contact_list = contacts.get("contacts", [])

        if contact_list:
            categories = set()
            for contact in contact_list:
                categories.update(contact.get("notificationCategorySubscriptions", []))

            required = {"SECURITY", "TECHNICAL", "BILLING"}
            missing = required - categories
            if missing:
                result.status = CheckStatus.FAIL
                result.evidence = f"Essential contacts configured but missing categories: {', '.join(sorted(missing))}"
            else:
                result.status = CheckStatus.PASS
                result.evidence = (
                    f"Essential contacts configured with {len(contact_list)} contact(s) covering SECURITY, TECHNICAL, and BILLING."
                )
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No essential contacts configured for the project."
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = "google-api-python-client not installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check essential contacts: {sanitize_discovery_warning(exc)}"
    return result

"""CIS Azure section 7 — virtual machine checks."""

from __future__ import annotations

from typing import Any

from ..aws_cis_benchmark import CheckStatus, CISCheckResult
from ._base import (
    _VM_SECTION,
    _pass_or_no_data,
)


def _check_7_1(compute_client: Any) -> CISCheckResult:
    """CIS 7.1 — Ensure Virtual Machines utilize Managed Disks."""
    result = CISCheckResult(
        check_id="7.1",
        title="Virtual machines use Managed Disks",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Migrate all VM disks to Managed Disks for improved reliability, security, and simplified management.",
        cis_section=_VM_SECTION,
    )
    try:
        vms = list(compute_client.virtual_machines.list_all())
        failing = []
        for vm in vms:
            vm_name = vm.name or "unknown"
            storage_profile = getattr(vm, "storage_profile", None)
            os_disk = getattr(storage_profile, "os_disk", None) if storage_profile else None
            managed_disk = getattr(os_disk, "managed_disk", None) if os_disk else None
            if managed_disk is None:
                failing.append(vm_name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"VMs not using Managed Disks: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            _pass_or_no_data(result, len(vms), "VM", f"All {len(vms)} VM(s) use Managed Disks.")
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check VM disk configuration: {exc}"
    return result


def _check_7_2(compute_client: Any) -> CISCheckResult:
    """CIS 7.2 — Ensure VMs use managed disks for OS disks."""
    result = CISCheckResult(
        check_id="7.2",
        title="VM OS disks use Managed Disks",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Migrate all VM OS disks to Managed Disks.",
        cis_section=_VM_SECTION,
    )
    try:
        vms = list(compute_client.virtual_machines.list_all())
        failing = []
        for vm in vms:
            vm_name = vm.name or "unknown"
            storage_profile = getattr(vm, "storage_profile", None)
            os_disk = getattr(storage_profile, "os_disk", None) if storage_profile else None
            managed_disk = getattr(os_disk, "managed_disk", None) if os_disk else None
            if managed_disk is None:
                failing.append(vm_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"VMs without managed OS disks: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            _pass_or_no_data(result, len(vms), "VM", f"All {len(vms)} VM(s) use Managed Disks for OS disks.")
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check VM managed disk configuration: {exc}"
    return result


def _check_7_3(compute_client: Any) -> CISCheckResult:
    """CIS 7.3 — Ensure OS and data disks are encrypted with CMK."""
    result = CISCheckResult(
        check_id="7.3",
        title="OS and data disks encrypted with customer-managed key",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Customer Managed Key encryption for all VM OS and data disks.",
        cis_section=_VM_SECTION,
    )
    try:
        disks = list(compute_client.disks.list())
        failing = []
        for disk in disks:
            disk_name = disk.name or "unknown"
            encryption = getattr(disk, "encryption", None)
            if encryption:
                enc_type = getattr(encryption, "type", "") or ""
                if "customermanaged" not in str(enc_type).lower().replace("_", "").replace("-", ""):
                    failing.append(disk_name)
            else:
                failing.append(disk_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Disks not encrypted with CMK: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            _pass_or_no_data(result, len(disks), "disk", f"All {len(disks)} disk(s) are encrypted with Customer Managed Key.")
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check disk encryption settings: {exc}"
    return result


def _check_7_4(compute_client: Any) -> CISCheckResult:
    """CIS 7.4 — Ensure only approved extensions are installed on VMs."""
    result = CISCheckResult(
        check_id="7.4",
        title="Only approved VM extensions installed",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Review all VM extensions and remove any unapproved or unnecessary extensions.",
        cis_section=_VM_SECTION,
    )
    try:
        vms = list(compute_client.virtual_machines.list_all())
        vm_extensions: list[str] = []
        for vm in vms:
            vm_name = vm.name or "unknown"
            resources = getattr(vm, "resources", []) or []
            for ext in resources:
                ext_name = getattr(ext, "name", "unknown") or "unknown"
                vm_extensions.append(f"{vm_name}/{ext_name}")
        if vm_extensions:
            # There is no approved-extension list to evaluate against, so this
            # is an inventory for review, not a compliance verdict.
            result.status = CheckStatus.NO_DATA
            result.evidence = (
                f"Not evaluated — no approved-extension list is configured. Found {len(vm_extensions)} extension(s) "
                f"across {len(vms)} VM(s) for manual review: {', '.join(vm_extensions[:10])}"
            )
            result.resource_ids = vm_extensions[:20]
        elif vms:
            result.status = CheckStatus.PASS
            result.evidence = f"No extensions found on {len(vms)} VM(s)."
        else:
            result.status = CheckStatus.NO_DATA
            result.evidence = "No VM(s) were discovered; this check has no data and cannot report PASS."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check VM extensions: {exc}"
    return result


def _check_7_5(compute_client: Any) -> CISCheckResult:
    """CIS 7.5 — Ensure latest OS patches are applied to VMs."""
    result = CISCheckResult(
        check_id="7.5",
        title="Latest OS patches applied to VMs",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable automatic OS updates or apply latest patches to all VMs. Use Azure Update Management for compliance tracking.",  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        cis_section=_VM_SECTION,
    )
    try:
        vms = list(compute_client.virtual_machines.list_all())
        result.status = CheckStatus.NO_DATA
        result.evidence = (
            f"Not evaluated — found {len(vms)} VM(s); OS patch status requires Azure Update Management or "
            "Microsoft Defender for Cloud recommendations. Verify patch compliance in "
            "Azure Portal > Update Management or Defender for Cloud > Recommendations."
        )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not list virtual machines: {exc}"
    return result


def _check_7_6(compute_client: Any) -> CISCheckResult:
    """CIS 7.6 — Ensure endpoint protection is installed on VMs."""
    result = CISCheckResult(
        check_id="7.6",
        title="Endpoint protection installed on VMs",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Install an endpoint protection solution (e.g., Microsoft Defender for Endpoint) on all VMs.",
        cis_section=_VM_SECTION,
    )
    try:
        vms = list(compute_client.virtual_machines.list_all())
        vms_without_ep = []
        ep_extensions = {"microsoftmonitoringagent", "iaasantimalware", "endpointprotection", "mdatp", "mde.linux", "mde.windows"}
        for vm in vms:
            vm_name = vm.name or "unknown"
            resources = getattr(vm, "resources", []) or []
            has_ep = False
            for ext in resources:
                ext_type = (getattr(ext, "virtual_machine_extension_type", "") or "").lower()
                ext_name = (getattr(ext, "name", "") or "").lower()
                if ext_type in ep_extensions or ext_name in ep_extensions:
                    has_ep = True
                    break
            if not has_ep:
                vms_without_ep.append(vm_name)
        if vms_without_ep:
            result.status = CheckStatus.FAIL
            result.evidence = f"VMs without detected endpoint protection: {', '.join(vms_without_ep[:10])}"
            result.resource_ids = vms_without_ep
        else:
            _pass_or_no_data(result, len(vms), "VM", f"All {len(vms)} VM(s) have endpoint protection extensions installed.")
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check VM endpoint protection: {exc}"
    return result

# Separate opt-in mutation role for GCP Persistent Disk side-scan. This module
# does not modify the read-only connect-gcp identity.
resource "google_project_iam_custom_role" "sidescan" {
  project     = var.project_id
  role_id     = var.role_id
  title       = var.role_title
  description = "Opt-in snapshot, temporary disk, and collector attach/detach lifecycle for agent-bom side-scan."

  permissions = [
    "compute.disks.create",
    "compute.disks.createSnapshot",
    "compute.disks.delete",
    "compute.disks.get",
    "compute.disks.list",
    "compute.disks.use",
    "compute.instances.attachDisk",
    "compute.instances.detachDisk",
    "compute.instances.get",
    "compute.snapshots.create",
    "compute.snapshots.delete",
    "compute.snapshots.get",
    "compute.snapshots.list",
    "compute.snapshots.useReadOnly",
    "compute.globalOperations.get",
    "compute.zoneOperations.get",
  ]
}

resource "google_project_iam_member" "sidescan" {
  project = var.project_id
  role    = google_project_iam_custom_role.sidescan.name
  member  = var.member
}

# Artifact Registry data-plane read.
#
# roles/viewer covers metadata + GCS object reads, but Artifact Registry image
# *pull* (downloadArtifacts) is a data-plane permission not guaranteed by the
# primitive viewer role. Without it, GAR image SBOM extraction can fail.

resource "google_project_iam_member" "artifactregistry_reader" {
  count = var.assign_artifact_registry_reader ? 1 : 0

  project = var.project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.this.email}"
}

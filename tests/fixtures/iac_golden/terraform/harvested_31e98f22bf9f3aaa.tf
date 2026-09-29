
resource "google_vertex_ai_endpoint" "infer" {
  display_name              = "infer"
  enable_public_endpoint    = true
  region                    = "us-central1"
}

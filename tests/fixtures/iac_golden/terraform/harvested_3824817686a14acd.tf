
resource "google_vertex_ai_model" "m" {
  display_name = "fraud-model"
  region       = "us-central1"
}

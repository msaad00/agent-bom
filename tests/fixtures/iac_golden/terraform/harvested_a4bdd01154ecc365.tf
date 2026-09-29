
resource "snowflake_stage" "models" {
  name     = "snowpark_models"
  database = "ML"
  schema   = "PUBLIC"
  to       = "PUBLIC"
}

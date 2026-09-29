
resource "snowflake_stage" "models" {
  name     = "snowpark_models"
  database = "ML"
  schema   = "PUBLIC"
}

resource "snowflake_grant_privileges_to_account_role" "g" {
  account_role_name = "PUBLIC"
  privileges        = ["USAGE"]
  on_schema_object {
    object_type = "STAGE"
    object_name = "ML.PUBLIC.snowpark_models"
  }
}

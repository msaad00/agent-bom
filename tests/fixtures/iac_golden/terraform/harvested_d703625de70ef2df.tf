resource "aws_ecs_task_definition" "app" {
  family       = "app"
  network_mode = "host"
  user         = "1000"
}

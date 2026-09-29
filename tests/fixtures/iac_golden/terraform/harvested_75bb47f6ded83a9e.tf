
resource "aws_ecr_repository" "inference" {
  name                 = "llm-inference"
  image_tag_mutability = "MUTABLE"
}

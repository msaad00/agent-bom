resource "aws_redshift_cluster" "dw" {
  cluster_identifier  = "my-dw"
  node_type           = "dc2.large"
  encrypted           = true
  publicly_accessible = true
}

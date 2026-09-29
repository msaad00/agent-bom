resource "aws_opensearch_domain" "os" {
  domain_name = "my-domain"

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }
}

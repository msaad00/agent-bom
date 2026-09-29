resource "aws_elasticsearch_domain" "es" {
  domain_name = "my-domain"

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }

  logging {
    enabled = true
  }
}

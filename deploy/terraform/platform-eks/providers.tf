# Provider wiring for the one-apply platform root module.
#
# The aws provider is configured from var.region. The kubernetes and helm
# providers authenticate against the target EKS cluster — either the one this
# module provisions (var.create_cluster = true) or a pre-existing cluster
# referenced by data sources. Both paths resolve to the same locals
# (cluster_endpoint / cluster_ca / cluster_name) defined in main.tf, so the
# provider blocks never branch.
#
# Auth uses an exec plugin that calls `aws eks get-token`. This keeps the
# kubeconfig keyless: no long-lived cluster credentials are written to disk or
# into Terraform state. The AWS CLI must be on PATH where Terraform runs.

provider "aws" {
  region = var.region

  default_tags {
    tags = var.tags
  }
}

provider "kubernetes" {
  host                   = local.cluster_endpoint
  cluster_ca_certificate = base64decode(local.cluster_ca)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", local.cluster_name, "--region", var.region]
  }
}

provider "helm" {
  kubernetes {
    host                   = local.cluster_endpoint
    cluster_ca_certificate = base64decode(local.cluster_ca)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", local.cluster_name, "--region", var.region]
    }
  }
}

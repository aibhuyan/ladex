# Terraform fixture: AI infra with governance issues (and a clean resource that must be silent).

# GPU node pool -> detected; also missing a data_residency tag -> finding.
resource "google_container_node_pool" "training" {
  name    = "gpu-pool"
  cluster = "ml-cluster"
  node_config {
    machine_type = "a2-highgpu-1g"
    guest_accelerator {
      type  = "nvidia-tesla-a100"
      count = 1
    }
  }
  tags = {
    team = "ml"
  }
}

# Vector store with encryption explicitly disabled -> finding.
resource "aws_opensearch_domain" "vectors" {
  domain_name = "rag-vectors"
  encrypt_at_rest {
    enabled = false
  }
  tags = {
    data_residency = "eu-west-1"
  }
}

# Managed inference endpoint -> detected; has a residency tag -> no residency finding.
resource "aws_sagemaker_endpoint" "serving" {
  name = "llm-endpoint"
  tags = {
    data_residency = "eu-central-1"
  }
}

# A plain, non-AI resource -> Ladex must stay silent.
resource "aws_s3_bucket" "logs" {
  bucket = "app-logs"
}

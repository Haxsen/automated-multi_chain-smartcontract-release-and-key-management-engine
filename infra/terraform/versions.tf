terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # State contains resource ARNs and policies (no secret values - those are never managed
  # by Terraform). Use an encrypted, versioned, access-logged remote backend, e.g.:
  #
  # backend "s3" {
  #   bucket       = "my-org-terraform-state"
  #   key          = "web3-release/terraform.tfstate"
  #   region       = "us-east-1"
  #   encrypt      = true
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(var.tags, {
      Project   = "multi-chain-release-engine"
      ManagedBy = "terraform"
    })
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

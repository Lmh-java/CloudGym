# Harness-owned terraform scaffolding for AWS cases.
#
# Case `main.tf` files hold only the case's infrastructure (usually verbatim
# dataset content) and carry no terraform/provider configuration. At run time
# the control plane stages a case by copying its `*.tf` files together with
# this file into the run's working directory; terraform merges all `.tf` files
# in the directory into one configuration. Keep resource-free: version
# constraints, provider config, and harness-level variables only.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

# Intentionally has no default. Online runners inject this value only after a
# successful STS preflight against the machine-local sandbox configuration.
variable "expected_aws_account_id" {
  type        = string
  description = "Only AWS account in which this configuration may operate."

  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_aws_account_id))
    error_message = "expected_aws_account_id must be a 12-digit AWS account ID."
  }
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.expected_aws_account_id]
}

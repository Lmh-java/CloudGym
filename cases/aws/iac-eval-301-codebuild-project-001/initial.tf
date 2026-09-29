# Pre-existing: the CS class's build network and the store the autograder's output is kept
# in — the VPC named `autograder-vpc` and the one bucket in the account whose name starts
# with `artifact-bucket-`, marked as the store the class's build output is kept in.
#
# Nothing builds yet: at S0 the account holds no CodeBuild project at all, no identity
# trusted by codebuild.amazonaws.com, and the VPC holds no subnet and no security group of
# its own beyond the default group EC2 mints with every VPC. Nothing here gives any
# workload a way in or out, and nothing here satisfies the task.

resource "aws_vpc" "autograder_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "autograder-vpc"
  }
}

resource "aws_s3_bucket" "artifact_bucket" {
  bucket_prefix = "artifact-bucket-"
  force_destroy = true

  tags = {
    Store = "autograder-results"
  }
}

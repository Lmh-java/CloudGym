# Pre-existing: the two things the CS class already has in the account — the network it was
# given and the store its results are kept in.
#
# `autograder-vpc` is the single block the class was allocated out of the account's address
# plan: 64 addresses, and nothing is carved out of it yet. The results store is the one bucket
# whose name starts with `artifact-bucket-`, marked as the store the class's results are kept
# in.
#
# Nothing of the task exists yet: at S0 the VPC holds no segment at all and no security group
# of the class's own (only the VPC's own default group, which every VPC is created with and
# which nobody stood up), no identity in the account is trusted by codebuild.amazonaws.com, no
# grant on the store exists, and the account holds no CodeBuild project. Nothing here carries
# any of the marks the account's other owners put on what they keep.

resource "aws_vpc" "autograder_vpc" {
  cidr_block = "10.30.0.0/26"

  tags = {
    Name  = "autograder-vpc"
    class = "cs101"
  }
}

resource "aws_s3_bucket" "artifact_bucket" {
  bucket_prefix = "artifact-bucket-"
  force_destroy = true

  tags = {
    Store = "autograder-results"
    class = "cs101"
  }
}

# Pre-existing: the CS class's build network — the `autograder-vpc` VPC and the one
# isolated segment the class keeps in it for its builds. Both carry the class's own
# labels. Nothing builds yet: at S0 the VPC holds no security group of the class's own,
# no service role trusts CodeBuild, there is no results bucket and no CodeBuild project.

resource "aws_vpc" "autograder_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name  = "autograder-vpc"
    class = "cs101"
  }
}

resource "aws_subnet" "autograder_vpc_subnet" {
  vpc_id                  = aws_vpc.autograder_vpc.id
  cidr_block              = "10.0.0.0/24"
  map_public_ip_on_launch = false

  tags = {
    Name  = "autograder-build"
    class = "cs101"
  }
}

# Pre-existing: the network the orders application already runs in. Nothing resolves
# privately from it yet — at S0 the account holds no hosted zone at all (public or private),
# no record set, and main-vpc is associated with no zone. The zone that serves the domain and
# the endpoint record under it are the task.
#
# DNS support and DNS hostnames are on, which is what makes a private zone resolvable from
# inside the VPC at all: it is the first hop of the path the task has to end up with.

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "main-vpc"
  }
}

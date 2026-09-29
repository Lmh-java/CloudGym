# Pre-existing: the application network the orders workload runs in. Nothing
# resolves privately in it yet — at S0 the account holds no hosted zone for
# internal.example53.com, no record under it, and the VPC is associated with no
# private zone at all. The zone and the endpoint record are the task.

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "main-vpc"
  }
}

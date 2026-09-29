# Pre-existing: the reporting service's network, the VPC tagged Name=reporting-vpc on
# 10.0.0.0/16, and nothing inside it. At S0 the VPC holds no subnet of its own and runs no
# instance, and it is the only VPC in the account carrying that name. The subnet the task
# asks for, and the server that runs in it, do not exist yet.

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "reporting-vpc"
    App  = "reporting"
  }
}

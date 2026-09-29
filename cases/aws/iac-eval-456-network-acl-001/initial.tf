# Pre-existing: the shared-services network the task's rules refer to. The
# `shared-services` VPC (10.3.0.0/16) and `partner-gateway`, the one segment
# allocated so far inside the 10.3.0.0/18 partner range. Nothing of the task
# exists at S0: there is no VPC with CIDR 10.0.0.0/16, and the only network ACL
# in the account is the default one the shared VPC is born with, which carries
# the wide-open entries EC2 writes itself and no entry of anyone's.

resource "aws_vpc" "shared_services" {
  cidr_block = "10.3.0.0/16"

  tags = {
    Name  = "shared-services"
    Owner = "platform-team"
  }
}

resource "aws_subnet" "partner_gateway" {
  vpc_id     = aws_vpc.shared_services.id
  cidr_block = "10.3.0.0/20"

  tags = {
    Name  = "partner-gateway"
    Owner = "platform-team"
  }
}

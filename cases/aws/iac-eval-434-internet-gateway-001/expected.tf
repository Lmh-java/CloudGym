# IaC-Eval reference output for row 434 (provider/terraform blocks dropped; the pre-existing
# platform network copied verbatim from initial.tf). Never applied: this is the witness of the
# main intent carried out with nobody else acting on the account.
#
# The web tier's network takes 10.1.0.0/16 — the lowest range of the account's plan that is
# neither held by a network nor recorded as reserved when nobody else allocates anything.

resource "aws_vpc" "platform" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name                       = "platform-vpc"
    "address-plan"             = "10.0.0.0/8"
    "allocation:platform-core" = "10.0.0.0/16"
  }
}

resource "aws_vpc" "_" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "vpc"
  }
}

resource "aws_internet_gateway" "_" {
  vpc_id = aws_vpc._.id

  tags = {
    Name = "ig"
  }
}

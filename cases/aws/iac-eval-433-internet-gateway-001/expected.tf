# IaC-Eval row 433, reference output rewritten against the pre-existing platform network
# (provider/terraform blocks dropped; the gateway's attachment given an observable witness —
# a table in the new network carrying a default route out through the gateway, since a route
# to an internet gateway can only be created from the network that gateway is attached to).
#
# The clean witness of the main intent with nobody else acting: a new 10.0.0.0/16 network
# that hands out DNS hostnames, an internet gateway of its own attached to it, and one table
# in it whose default route leaves through that gateway. It is not the resolved outcome —
# with other principals acting, which gateway that network reaches the outside through and
# which table carries that way out is read off the account.

resource "aws_vpc" "platform" {
  cidr_block           = "10.70.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name     = "platform-vpc"
    Workload = "platform"
  }
}

resource "aws_vpc" "app" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "vpc"
  }
}

resource "aws_internet_gateway" "app" {
  vpc_id = aws_vpc.app.id

  tags = {
    Name = "ig"
  }
}

resource "aws_route_table" "app_edge" {
  vpc_id = aws_vpc.app.id

  tags = {
    Name = "vpc-edge-rt"
  }
}

resource "aws_route" "app_default" {
  route_table_id         = aws_route_table.app_edge.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.app.id
}

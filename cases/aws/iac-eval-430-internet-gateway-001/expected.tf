# IaC-Eval row 430, reference output rewritten against the pre-existing analytics network
# (provider/terraform blocks dropped, the `var.name` tag inlined per resource, the route
# table's inline `route` block hoisted into an aws_route so the route's target is observable,
# and the table bound to the segment it is meant to carry — a table carries nothing until
# something rides it).
#
# The clean witness of the main intent with nobody else acting: the network resolves DNS and
# hands out DNS hostnames, an internet gateway of its own is attached to it, and one route
# table in it carries the outward-facing segment out through that gateway. It is not the
# resolved outcome — with other principals acting, which gateway the network reaches the
# outside through, which table carries that way out, and which segments ride it is read off
# the account.

resource "aws_vpc" "analytics" {
  cidr_block           = "10.60.0.0/16"
  instance_tenancy     = "dedicated"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name     = "analytics-vpc"
    Workload = "analytics"
  }
}

resource "aws_subnet" "edge" {
  vpc_id     = aws_vpc.analytics.id
  cidr_block = "10.60.1.0/24"

  tags = {
    Name     = "analytics-edge-a"
    Tier     = "edge"
    Workload = "analytics"
  }
}

resource "aws_internet_gateway" "analytics" {
  vpc_id = aws_vpc.analytics.id

  tags = {
    Name     = "analytics-igw"
    Workload = "analytics"
  }
}

resource "aws_route_table" "analytics_egress" {
  vpc_id = aws_vpc.analytics.id

  tags = {
    Name     = "analytics-egress-rt"
    Workload = "analytics"
  }
}

resource "aws_route" "analytics_default" {
  route_table_id         = aws_route_table.analytics_egress.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.analytics.id
}

resource "aws_route_table_association" "edge" {
  subnet_id      = aws_subnet.edge.id
  route_table_id = aws_route_table.analytics_egress.id
}

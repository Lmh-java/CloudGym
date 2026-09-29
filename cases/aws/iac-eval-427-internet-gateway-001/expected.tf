# IaC-Eval row 427, reference output rewritten against the pre-existing VPC
# (provider/terraform blocks dropped, the subnet count unrolled, the route table's inline
# route hoisted into an aws_route so the route's target is observable).
#
# The clean witness of the main intent with nobody else acting: two new public subnets in
# distinct availability zones, an internet gateway on the VPC, one route table carrying a
# default route through that gateway, and both new subnets associated with it. It is not
# the resolved outcome — with other principals acting, which gateway and which table the
# work lands on is read off the account.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "app" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name     = "app-vpc"
    Workload = "storefront"
  }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.app.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name     = "app-private-a"
    Tier     = "private"
    Workload = "storefront"
  }
}

resource "aws_route_table" "shared" {
  vpc_id = aws_vpc.app.id

  tags = {
    Name     = "app-shared-rt"
    Routing  = "shared"
    Workload = "storefront"
  }
}

resource "aws_subnet" "public_a" {
  vpc_id            = aws_vpc.app.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name     = "app-public-a"
    Tier     = "public"
    Workload = "storefront"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id            = aws_vpc.app.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name     = "app-public-b"
    Tier     = "public"
    Workload = "storefront"
  }
}

resource "aws_internet_gateway" "app" {
  vpc_id = aws_vpc.app.id

  tags = {
    Name     = "app-igw"
    Workload = "storefront"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.app.id

  tags = {
    Name     = "app-public-rt"
    Workload = "storefront"
  }
}

resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.app.id
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

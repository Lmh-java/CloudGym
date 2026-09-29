# IaC-Eval row 429, reference output rewritten against the pre-existing payments network
# (provider/terraform blocks dropped, the subnet count unrolled, the route table's inline
# route hoisted into an aws_route so the route's target is observable).
#
# The clean witness of the main intent with nobody else acting: two new public subnets in
# distinct availability zones, an internet gateway on the VPC, one route table carrying a
# default route through that gateway, and both new subnets associated with it. It is not
# the resolved outcome — with other principals acting, which gateway and which table the
# public tier lands on is read off the account.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "payments" {
  cidr_block           = "10.40.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name     = "payments-vpc"
    Workload = "payments"
  }
}

resource "aws_subnet" "core_a" {
  vpc_id            = aws_vpc.payments.id
  cidr_block        = "10.40.10.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name     = "payments-core-a"
    Tier     = "core"
    Workload = "payments"
  }
}

resource "aws_subnet" "core_b" {
  vpc_id            = aws_vpc.payments.id
  cidr_block        = "10.40.11.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name     = "payments-core-b"
    Tier     = "core"
    Workload = "payments"
  }
}

resource "aws_route_table" "edge" {
  vpc_id = aws_vpc.payments.id

  tags = {
    Name     = "payments-edge-rt"
    Routing  = "edge"
    Workload = "payments"
  }
}

resource "aws_subnet" "public_a" {
  vpc_id            = aws_vpc.payments.id
  cidr_block        = "10.40.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name     = "payments-public-a"
    Tier     = "public"
    Workload = "payments"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id            = aws_vpc.payments.id
  cidr_block        = "10.40.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name     = "payments-public-b"
    Tier     = "public"
    Workload = "payments"
  }
}

resource "aws_internet_gateway" "payments" {
  vpc_id = aws_vpc.payments.id

  tags = {
    Name     = "payments-igw"
    Workload = "payments"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.payments.id

  tags = {
    Name     = "payments-public-rt"
    Workload = "payments"
  }
}

resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.payments.id
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

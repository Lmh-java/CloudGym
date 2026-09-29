resource "aws_vpc" "dependency" {
  cidr_block = "10.246.0.0/16"
}

resource "aws_internet_gateway" "dependency" {
  vpc_id = aws_vpc.dependency.id
}

resource "aws_route_table" "dependency" {
  vpc_id = aws_vpc.dependency.id
}

resource "aws_route" "capability" {
  route_table_id         = aws_route_table.dependency.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.dependency.id
}

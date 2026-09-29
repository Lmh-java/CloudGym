resource "aws_vpc" "dependency" {
  cidr_block = "10.245.0.0/16"
}

resource "aws_subnet" "dependency" {
  vpc_id     = aws_vpc.dependency.id
  cidr_block = "10.245.1.0/24"
}

resource "aws_route_table" "dependency" {
  vpc_id = aws_vpc.dependency.id
}

resource "aws_route_table_association" "capability" {
  subnet_id      = aws_subnet.dependency.id
  route_table_id = aws_route_table.dependency.id
}

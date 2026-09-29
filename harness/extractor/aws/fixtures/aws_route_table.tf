resource "aws_vpc" "dependency" {
  cidr_block = "10.244.0.0/16"
}

resource "aws_route_table" "capability" {
  vpc_id = aws_vpc.dependency.id
}

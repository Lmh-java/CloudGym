resource "aws_vpc" "dependency" {
  cidr_block = "10.243.0.0/16"
}

resource "aws_internet_gateway" "capability" {
  vpc_id = aws_vpc.dependency.id
}

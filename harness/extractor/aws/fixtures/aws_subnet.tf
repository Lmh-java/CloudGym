resource "aws_vpc" "dependency" {
  cidr_block = "10.242.0.0/16"
}

resource "aws_subnet" "capability" {
  vpc_id     = aws_vpc.dependency.id
  cidr_block = "10.242.1.0/24"
}

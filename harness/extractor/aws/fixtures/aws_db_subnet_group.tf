data "aws_availability_zones" "dependency" {
  state = "available"
}

resource "aws_vpc" "dependency" {
  cidr_block = "10.251.0.0/16"
}

resource "aws_subnet" "dependency" {
  count             = 2
  vpc_id            = aws_vpc.dependency.id
  cidr_block        = cidrsubnet(aws_vpc.dependency.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.dependency.names[count.index]
}

resource "aws_db_subnet_group" "capability" {
  name_prefix = "cloudgym-capability-"
  subnet_ids  = aws_subnet.dependency[*].id
}

data "aws_availability_zones" "dependency" {
  state = "available"
}

resource "aws_vpc" "dependency" {
  cidr_block = "10.255.0.0/16"
}

resource "aws_subnet" "dependency" {
  count             = 2
  vpc_id            = aws_vpc.dependency.id
  cidr_block        = cidrsubnet(aws_vpc.dependency.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.dependency.names[count.index]
}

resource "aws_security_group" "dependency" {
  name_prefix = "cloudgym-capability-"
  description = "cloudgym extractor capability fixture"
  vpc_id      = aws_vpc.dependency.id
}

resource "aws_lb" "capability" {
  name_prefix        = "cwcap-"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.dependency.id]
  subnets            = aws_subnet.dependency[*].id
}

resource "aws_vpc" "dependency" {
  cidr_block = "10.242.0.0/16"
}

resource "aws_security_group" "capability" {
  name_prefix = "cloudgym-capability-"
  description = "cloudgym extractor capability fixture"
  vpc_id      = aws_vpc.dependency.id
}

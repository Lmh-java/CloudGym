data "aws_ami" "dependency" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_vpc" "dependency" {
  cidr_block = "10.250.0.0/16"
}

resource "aws_subnet" "dependency" {
  vpc_id     = aws_vpc.dependency.id
  cidr_block = "10.250.1.0/24"
}

resource "aws_instance" "capability" {
  ami           = data.aws_ami.dependency.id
  instance_type = "t3.micro" # the SCP's OnlyCheapInstanceTypes guardrail admits t2.micro/t3.micro/t3.small
  subnet_id     = aws_subnet.dependency.id

  tags = {
    Name = "cloudgym-capability"
  }
}

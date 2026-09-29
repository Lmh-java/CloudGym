# IaC-Eval row 240, reference output rewritten against the pre-existing reporting VPC
# (provider/terraform blocks dropped; the VPC copied verbatim from initial.tf instead of
# being created here).
#
# The clean witness of the main intent with nobody else acting: one subnet cut out of
# reporting-vpc — 10.0.1.0/24, the first free /24 of the VPC when nothing else has been
# allocated out of it — holding one t2.micro instance launched from the image the AMI
# lookup resolves to, Canonical's most recent Ubuntu 20.04 (focal) amd64 server AMI.

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "reporting-vpc"
    App  = "reporting"
  }
}

resource "aws_subnet" "example_subnet" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
}

data "aws_ami" "ubuntu_ami" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"]
}

resource "aws_instance" "example_instance" {
  ami           = data.aws_ami.ubuntu_ami.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.example_subnet.id
}

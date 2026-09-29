# IaC-Eval row 127, reference output rewritten against the pre-existing application VPC
# (provider/terraform blocks dropped, the reference's `data.aws_availability_zones` lookup
# replaced by the two zones the prompt names, the VPC copied verbatim from initial.tf).
#
# The clean witness of the main intent with nobody else acting: two subnets of app-vpc,
# one in us-east-1a and one in us-east-1b, each holding one t2.micro instance launched
# from the latest Amazon Linux 2 AMI with a 50 GB EBS root volume. The /24s below are the
# first two free ranges of the VPC when nothing else has been allocated out of it.

data "aws_ami" "latest_amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

resource "aws_vpc" "app" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "app-vpc"
    App  = "storefront"
  }
}

resource "aws_subnet" "subnet_a" {
  vpc_id            = aws_vpc.app.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name = "storefront-a"
    App  = "storefront"
  }
}

resource "aws_subnet" "subnet_b" {
  vpc_id            = aws_vpc.app.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name = "storefront-b"
    App  = "storefront"
  }
}

resource "aws_instance" "ec2_instance_a" {
  ami           = data.aws_ami.latest_amazon_linux_2.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.subnet_a.id

  root_block_device {
    volume_size = 50
  }

  tags = {
    Name = "storefront-a-1"
    App  = "storefront"
  }
}

resource "aws_instance" "ec2_instance_b" {
  ami           = data.aws_ami.latest_amazon_linux_2.id
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.subnet_b.id

  root_block_device {
    volume_size = 50
  }

  tags = {
    Name = "storefront-b-1"
    App  = "storefront"
  }
}

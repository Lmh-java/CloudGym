# IaC-Eval row 188, reference output rewritten against the pre-existing ledger network
# (provider/terraform blocks dropped, the reference's `data.aws_availability_zones` lookup
# replaced by the two zones the prompt names, the VPC copied verbatim from initial.tf).
#
# The clean witness of the main intent with nobody else acting: two subnets of ledger-vpc,
# one in us-east-1a and one in us-east-1b, each holding one t2.micro instance launched from
# the latest Amazon Linux 2 AMI with a 50 GB EBS root volume, each carrying the network's
# own attribution. The two /24s below are simply the bottom of the VPC — what is free when
# nothing else has been cut out of it.

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

resource "aws_vpc" "ledger" {
  cidr_block           = "10.60.0.0/22"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name       = "ledger-vpc"
    App        = "ledger"
    CostCenter = "LEDGER-4471"
  }
}

resource "aws_subnet" "subnet_a" {
  vpc_id            = aws_vpc.ledger.id
  cidr_block        = "10.60.0.0/24"
  availability_zone = "us-east-1a"

  tags = {
    Name       = "ledger-a"
    App        = "ledger"
    CostCenter = "LEDGER-4471"
  }
}

resource "aws_subnet" "subnet_b" {
  vpc_id            = aws_vpc.ledger.id
  cidr_block        = "10.60.1.0/24"
  availability_zone = "us-east-1b"

  tags = {
    Name       = "ledger-b"
    App        = "ledger"
    CostCenter = "LEDGER-4471"
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
    Name       = "ledger-a-1"
    App        = "ledger"
    CostCenter = "LEDGER-4471"
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
    Name       = "ledger-b-1"
    App        = "ledger"
    CostCenter = "LEDGER-4471"
  }
}

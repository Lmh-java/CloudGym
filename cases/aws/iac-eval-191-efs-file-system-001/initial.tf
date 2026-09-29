# Pre-existing: the render team's network and the file system its workers are meant to share.
# The VPC `shared-media-vpc` on 10.0.0.0/16 holds two private subnets, one per zone
# (10.0.1.0/24 and 10.0.2.0/24) — no gateway, no route out — and the account holds the EFS file
# system `my-efs`, created and then left alone: it runs on the burst throughput the account
# hands out by default, carries no lifecycle configuration (so nothing it holds ever moves to
# Infrequent Access storage), and has no mount target in any subnet, so nothing in the network
# can reach it.
#
# At S0 the network runs no instance of its own and holds no security group but the VPC's
# default one. The mount targets, the file system's Infrequent Access transition, the security
# group that admits NFS, and the two workers are the task's diff.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "my_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "shared-media-vpc"
    App  = "shared-media"
  }
}

resource "aws_subnet" "private_subnet_1" {
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "shared-media-private-1"
    App  = "shared-media"
  }
}

resource "aws_subnet" "private_subnet_2" {
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "shared-media-private-2"
    App  = "shared-media"
  }
}

resource "aws_efs_file_system" "efs" {
  creation_token  = "my-efs"
  throughput_mode = "bursting"

  tags = {
    Name  = "my-efs"
    App   = "shared-media"
    Owner = "media-team"
  }
}

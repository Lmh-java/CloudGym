# IaC-Eval reference output for row 130 (provider/terraform blocks dropped; the outputs dropped;
# the network and the file system pre-exist as in initial.tf and keep the throughput mode and the
# attribution they were created with). The clean witness of the task with nobody else acting:
# `my-efs` carries the reference's Infrequent Access transition and has a mount target in each of
# the two private subnets, the `ec2_sg` group in the VPC admits 22, 80 and the NFS port the mounts
# need and lets everything out, and two t2.micro servers run one per private subnet with user data
# that mounts the file system at /mnt/efs.
#
# Two fidelity fixes to the reference, neither of which changes what it builds: the AMI lookup
# filters on `amzn2-ami-hvm-*` (the row's own prompt asks for the newest Amazon Linux 2, while the
# reference's filter names an Ubuntu 24.04 image), and the instances carry the group as
# `vpc_security_group_ids` rather than `security_groups`, which is the attribute that takes a
# group id inside a VPC. This file is never applied.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "my_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "shared-scratch-vpc"
    App  = "shared-scratch"
  }
}

resource "aws_subnet" "private_subnet_1" {
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "shared-scratch-private-1"
    App  = "shared-scratch"
  }
}

resource "aws_subnet" "private_subnet_2" {
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "shared-scratch-private-2"
    App  = "shared-scratch"
  }
}

resource "aws_efs_file_system" "efs" {
  creation_token  = "my-efs"
  throughput_mode = "bursting"

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  tags = {
    Name  = "my-efs"
    App   = "shared-scratch"
    Owner = "scratch-team"
  }
}

resource "aws_security_group" "ec2_sg" {
  vpc_id = aws_vpc.my_vpc.id
  name   = "ec2_sg"
}

resource "aws_vpc_security_group_ingress_rule" "ingress1" {
  security_group_id = aws_security_group.ec2_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  ip_protocol       = "tcp"
  to_port           = 80
}

resource "aws_vpc_security_group_ingress_rule" "ingress2" {
  security_group_id = aws_security_group.ec2_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  ip_protocol       = "tcp"
  to_port           = 22
}

# Allow NFS traffic
resource "aws_vpc_security_group_ingress_rule" "ingress3" {
  security_group_id = aws_security_group.ec2_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 2049
  ip_protocol       = "tcp"
  to_port           = 2049
}

resource "aws_vpc_security_group_egress_rule" "egress1" {
  security_group_id = aws_security_group.ec2_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_efs_mount_target" "mount_target_1" {
  file_system_id  = aws_efs_file_system.efs.id
  subnet_id       = aws_subnet.private_subnet_1.id
  security_groups = [aws_security_group.ec2_sg.id]
}

resource "aws_efs_mount_target" "mount_target_2" {
  file_system_id  = aws_efs_file_system.efs.id
  subnet_id       = aws_subnet.private_subnet_2.id
  security_groups = [aws_security_group.ec2_sg.id]
}

data "aws_ami" "amzn2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_instance" "ec2_instance_1" {
  ami                    = data.aws_ami.amzn2.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.private_subnet_1.id
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]

  user_data = <<-EOF
              #!/bin/bash
              mkdir /mnt/efs
              mount -t efs ${aws_efs_file_system.efs.id}:/ /mnt/efs
              EOF
}

resource "aws_instance" "ec2_instance_2" {
  ami                    = data.aws_ami.amzn2.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.private_subnet_2.id
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]

  user_data = <<-EOF
              #!/bin/bash
              mkdir /mnt/efs
              mount -t efs ${aws_efs_file_system.efs.id}:/ /mnt/efs
              EOF
}

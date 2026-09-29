resource "aws_vpc" "dependency" {
  cidr_block = "10.248.0.0/16"
}

resource "aws_subnet" "dependency" {
  vpc_id            = aws_vpc.dependency.id
  cidr_block        = "10.248.1.0/24"
  availability_zone = "us-east-1a"
}

resource "aws_security_group" "dependency" {
  name_prefix = "cloudgym-capability-efs-a-"
  vpc_id      = aws_vpc.dependency.id
}

resource "aws_security_group" "second" {
  name_prefix = "cloudgym-capability-efs-b-"
  vpc_id      = aws_vpc.dependency.id
}

resource "aws_efs_file_system" "dependency" {
  creation_token = "cloudgym-capability-efs-mt"
}

resource "aws_efs_mount_target" "capability" {
  file_system_id  = aws_efs_file_system.dependency.id
  subnet_id       = aws_subnet.dependency.id
  security_groups = [aws_security_group.dependency.id, aws_security_group.second.id]
}

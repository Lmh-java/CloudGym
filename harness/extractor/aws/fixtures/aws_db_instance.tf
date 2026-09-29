data "aws_availability_zones" "dependency" {
  state = "available"
}

resource "aws_vpc" "dependency" {
  cidr_block = "10.252.0.0/16"
}

resource "aws_subnet" "dependency" {
  count             = 2
  vpc_id            = aws_vpc.dependency.id
  cidr_block        = cidrsubnet(aws_vpc.dependency.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.dependency.names[count.index]
}

resource "aws_db_subnet_group" "dependency" {
  name_prefix = "cloudgym-capability-"
  subnet_ids  = aws_subnet.dependency[*].id
}

# db.t3.micro single-AZ is what the SCP's OnlyCheapDatabaseClasses / NoMultiAzDatabases admit.
# The password is a throwaway for a private, unreachable fixture instance.
resource "aws_db_instance" "capability" {
  identifier_prefix       = "cloudgym-capability-"
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  storage_type            = "gp2"
  username                = "cloudgym"
  password                = "CloudGymCapability1"
  db_subnet_group_name    = aws_db_subnet_group.dependency.name
  publicly_accessible     = false
  multi_az                = false
  backup_retention_period = 0
  skip_final_snapshot     = true
  deletion_protection     = false
  apply_immediately       = true
}

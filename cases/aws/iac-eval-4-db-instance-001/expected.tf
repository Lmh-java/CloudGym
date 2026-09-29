# IaC-Eval reference output for row 4 (provider/terraform blocks dropped).
#
# Deviations from the dataset's HCL, all fidelity fixes rather than task changes: the record
# names are inside the zone they are created in (`public-db.example53.com` rather than the
# reference's `public-db.example.com`, which Route 53 rejects as not permitted in zone
# `example53.com`); the publicly accessible instance sits in the same DB subnet group as the
# internal one so the case does not depend on a default VPC existing in the sandbox account,
# which is in turn why the pre-existing VPC carries an internet gateway; and the master
# password is a value that satisfies the RDS minimum length. The VPC, the gateway and the
# first subnet are carried over verbatim from initial.tf.
#
# The clean witness of the main intent with nobody else acting: a second subnet carved out of
# the free half of the VPC's range in another availability zone, a DB subnet group named
# `main` over both subnets, the two databases in it, and split-horizon DNS for
# `example53.com` — a private zone associated with the VPC answering the internal name and a
# public zone answering the external one.

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "app-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "app-igw"
  }
}

resource "aws_subnet" "maina" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.0.0/25"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "app-subnet-a"
  }
}

# The second subnet the task adds, in another availability zone
resource "aws_subnet" "mainb" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.0.128/25"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "app-subnet-b"
  }
}

# Subnet group for the databases
resource "aws_db_subnet_group" "main" {
  name       = "main"
  subnet_ids = [aws_subnet.maina.id, aws_subnet.mainb.id]
}

# RDS instances
resource "aws_db_instance" "internal" {
  # Internal DB configuration
  allocated_storage    = 20
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  identifier           = "internal"
  username             = "dbadmin"
  password             = "ChangeMe12345"
  db_subnet_group_name = aws_db_subnet_group.main.name
  skip_final_snapshot  = true
}

resource "aws_db_instance" "public" {
  # Public DB configuration
  publicly_accessible  = true
  allocated_storage    = 20
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  identifier           = "public"
  username             = "dbadmin"
  password             = "ChangeMe12345"
  db_subnet_group_name = aws_db_subnet_group.main.name
  skip_final_snapshot  = true
}

# Route 53 Public Hosted Zone for external users
resource "aws_route53_zone" "public" {
  name = "example53.com"
}

# Route 53 Private Hosted Zone for internal users
resource "aws_route53_zone" "private" {
  name = "example53.com"
  vpc {
    vpc_id = aws_vpc.main.id
  }
}

# Route 53 Record for Public DB (External Endpoint)
resource "aws_route53_record" "public_db" {
  zone_id = aws_route53_zone.public.zone_id
  name    = "public-db.example53.com"
  type    = "CNAME"
  ttl     = "300"
  records = [aws_db_instance.public.address]
}

# Route 53 Record for Internal DB (Internal Endpoint)
resource "aws_route53_record" "internal_db" {
  zone_id = aws_route53_zone.private.zone_id
  name    = "internal-db.example53.com"
  type    = "CNAME"
  ttl     = "300"
  records = [aws_db_instance.internal.address]
}

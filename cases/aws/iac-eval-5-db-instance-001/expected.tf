# IaC-Eval reference output for row 5 (provider/terraform blocks dropped).
#
# Three deviations from the dataset's HCL, all fidelity fixes rather than task changes:
# the replicas are identified as `replica-1` and `replica-2` (the names the prompt asks
# for; the dataset HCL called the blocks `replica_1`/`replica_2` but identified the
# instances `mydb-replica-1`/`mydb-replica-2`), the records resolve to the replicas'
# `address` rather than `endpoint` (the endpoint carries `:5432`, which Route 53 rejects
# as a CNAME value), and the pre-existing `primary` instance and `main` zone are carried
# over verbatim from initial.tf, ownership tags included.

resource "aws_db_instance" "primary" {
  identifier              = "primary"
  allocated_storage       = 20
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  username                = "dbadmin"
  password                = "your_password_here"
  skip_final_snapshot     = true
  backup_retention_period = 7

  tags = {
    Application = "orders"
    Owner       = "orders-team"
  }
}

resource "aws_db_instance" "replica_1" {
  replicate_source_db = aws_db_instance.primary.identifier
  instance_class      = "db.t3.micro"
  identifier          = "replica-1"
  skip_final_snapshot = true
}

resource "aws_db_instance" "replica_2" {
  replicate_source_db = aws_db_instance.primary.identifier
  instance_class      = "db.t3.micro"
  identifier          = "replica-2"
  skip_final_snapshot = true
}

# Route53 Hosted Zone
resource "aws_route53_zone" "main" {
  name = "example53.com"

  tags = {
    Application = "orders"
    Owner       = "orders-team"
  }
}

# Route53 Records for each RDS Read Replica with a Weighted Routing Policy
resource "aws_route53_record" "replica_1_cname" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "replica1.example53.com"
  type    = "CNAME"
  records = [aws_db_instance.replica_1.address]
  ttl     = "60"
  weighted_routing_policy {
    weight = 10
  }
  set_identifier = "replica-1-record"
}

resource "aws_route53_record" "replica_2_cname" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "replica2.example53.com"
  type    = "CNAME"
  records = [aws_db_instance.replica_2.address]
  ttl     = "60"
  weighted_routing_policy {
    weight = 20
  }
  set_identifier = "replica-2-record"
}

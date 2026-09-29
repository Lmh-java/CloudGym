# Pre-existing: the application's main database and the public hosted zone the
# account already serves `example53.com` from. Both carry the application's
# ownership tags, which is how the account records who a resource belongs to.
#
# Nothing of the task exists at S0: `primary` has no read replicas, and the zone
# answers nothing but its own apex records — there is no CNAME for a replica and
# no weighted routing anywhere under the domain.

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

resource "aws_route53_zone" "main" {
  name = "example53.com"

  tags = {
    Application = "orders"
    Owner       = "orders-team"
  }
}

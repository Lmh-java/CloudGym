# The smallest instance the SCP admits; ~5-10 minutes to create, the snapshot 1-3 more.
resource "aws_db_instance" "dependency" {
  identifier_prefix   = "cloudgym-capability-"
  engine              = "postgres"
  engine_version      = "16"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "cloudgym"
  password            = "CapabilityCheck1234"
  skip_final_snapshot = true
  apply_immediately   = true
}

# The identifier follows the instance's generated name, so it never collides on reuse.
resource "aws_db_snapshot" "capability" {
  db_instance_identifier = aws_db_instance.dependency.identifier
  db_snapshot_identifier = "${aws_db_instance.dependency.identifier}-snap"
}

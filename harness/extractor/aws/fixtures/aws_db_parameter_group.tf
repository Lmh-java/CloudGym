resource "aws_db_parameter_group" "capability" {
  name_prefix = "cloudgym-capability-"
  family      = "postgres16"

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
}

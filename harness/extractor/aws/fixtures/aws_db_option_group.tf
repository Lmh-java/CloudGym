resource "aws_db_option_group" "capability" {
  name_prefix              = "cloudgym-capability-"
  option_group_description = "CloudGym extractor capability check"
  engine_name              = "mysql"
  major_engine_version     = "8.0"

  option {
    option_name = "MARIADB_AUDIT_PLUGIN"

    option_settings {
      name  = "SERVER_AUDIT_EVENTS"
      value = "CONNECT"
    }
  }
}

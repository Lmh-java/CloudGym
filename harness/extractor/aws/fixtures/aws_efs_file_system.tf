resource "aws_efs_file_system" "capability" {
  creation_token   = "cloudgym-capability-efs"
  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"
  encrypted        = true

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  tags = {
    Name = "cloudgym-capability"
  }
}

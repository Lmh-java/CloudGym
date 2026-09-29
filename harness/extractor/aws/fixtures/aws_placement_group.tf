resource "aws_placement_group" "capability" {
  # aws_placement_group has no name_prefix; a leaked previous run fails the apply visibly.
  name     = "cloudgym-capability-pg"
  strategy = "cluster"

  tags = {
    Name = "cloudgym-capability"
  }
}

# Pre-existing: the design team's cloud desktop, as it stands before anyone asks for backups.
# `cloud-desktop` is the machine itself — running on the account's current Amazon Linux image
# and carrying the record every resource in this account carries: the name it is known by and
# the team accountable for it.
#
# It was provisioned a size larger than the team ever used, and it has never been backed up.
# Nothing here satisfies the task: the machine stands at `t3.small`, not `t2.micro`, and the
# account holds no backup vault, no backup plan, no backup selection and no role AWS Backup
# could assume.

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

resource "aws_instance" "cloud_desktop" {
  ami           = data.aws_ami.al2023.id
  instance_type = "t3.small"

  tags = {
    Name = "cloud-desktop"
    Team = "design"
  }
}

# Pre-existing: the analytics team's cloud desktop, as it stands before anyone asks for backups.
#
# `analyst-desktop` is the machine itself, running on the account's current Amazon Linux 2023
# image and carrying the record every resource in this account carries: the name it is known by
# and the team accountable for it. `analyst-desktop` is also the SSH key pair the team logs in
# with; the machine was launched against it, which is the only way a key ever reaches a machine,
# so the key pair is as old as the desktop.
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

resource "aws_key_pair" "analyst_desktop" {
  key_name   = "analyst-desktop"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCpXJrhzZcJBdo+JEozH/hMtYJ9OS12I8HiD0ClrX5B+Zz+nVFneX3ip/1Woli4fAloZaho21yDXM3WKIwIyeEfTpge+6xA0DfIQ+NH8JOCtwr9JceJizFXWqkxgx+btydf8iqt2GR0QNygVwpqQsyN0rJY/bZePfT5kiXiDbgR9CVv57fxQp0feU5H+aQtRau4RBLlV1Ie9UPcb2NPI8rjNa1EEPNLO4FeQsQvE5FTnczaMl52rrBy44Be6eQIBVvEKEqReXjx7PeAkmiwhC0U7hcV5KBIDIgfA6zNKaiuySfnkwwP+ueJK0x1j4GQ3KE7FzQRkRFifb/ypQBvC/I7 analyst-desktop"
}

resource "aws_instance" "analyst_desktop" {
  ami           = data.aws_ami.al2023.id
  instance_type = "t3.small"
  key_name      = aws_key_pair.analyst_desktop.key_name

  tags = {
    Name = "analyst-desktop"
    Team = "analytics"
  }
}

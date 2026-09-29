# IaC-Eval reference output for row 309 (provider/terraform blocks dropped; the key file the row
# reads inlined; the pre-existing desktop and its key pair carried over from initial.tf with the
# task applied to them), as the clean witness of the main intent with nobody else acting on the
# account: the analytics team's cloud desktop running at the size the row gives it, reachable
# with the team's key as before, and backed up every day at midnight by AWS Backup into a vault
# of its own through a role AWS Backup can assume, each restore point kept for seven days.
#
# Deviations from the row's reference text, all of them the witness's choice rather than the
# task's:
#   * the public key. The row reads it from `./supplement/key.pub`, which the case cannot carry;
#     the key the team already logs in with is inlined instead, and the key pair is named so the
#     machine can be launched against it by name.
#   * the names. The row calls its resources `cloud_desktop_backup_plan`,
#     `cloud_desktop_backup_valut` and `backup`; this account names a resource after the workload
#     it serves and what it does for it.
#   * the instance and its key pair. The row launches the one and registers the other; both are
#     already there, the machine at `t3.small`, and what the task changes on it is its size — the
#     row's own `t2.micro`.
# The row's schedule, its seven-day lifecycle on the plan rule, its `WindowsVSS` advanced backup
# setting on resource type EC2, its vault, its selection over the instance's ARN and the managed
# policy on the backup role are reproduced as the row describes.
#
# This file is never applied: it is what the account would hold with nobody else in it.

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
  instance_type = "t2.micro"
  key_name      = aws_key_pair.analyst_desktop.key_name

  tags = {
    Name = "analyst-desktop"
    Team = "analytics"
  }
}

resource "aws_backup_vault" "analyst_desktop" {
  name = "analyst-desktop-backup-vault"
}

resource "aws_backup_plan" "analyst_desktop" {
  name = "analyst-desktop-backup-plan"

  rule {
    rule_name         = "analyst-desktop-daily"
    target_vault_name = aws_backup_vault.analyst_desktop.name
    schedule          = "cron(0 0 * * ? *)"

    lifecycle {
      delete_after = 7
    }
  }

  advanced_backup_setting {
    backup_options = {
      WindowsVSS = "enabled"
    }
    resource_type = "EC2"
  }
}

data "aws_iam_policy_document" "backup_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "backup" {
  name               = "analyst-desktop-backup-role"
  assume_role_policy = data.aws_iam_policy_document.backup_assume_role.json
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_backup_selection" "analyst_desktop" {
  name         = "analyst-desktop-backup"
  iam_role_arn = aws_iam_role.backup.arn
  plan_id      = aws_backup_plan.analyst_desktop.id

  resources = [
    aws_instance.analyst_desktop.arn,
  ]
}

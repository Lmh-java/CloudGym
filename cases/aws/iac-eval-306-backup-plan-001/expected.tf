# IaC-Eval reference output for row 306 (provider/terraform blocks dropped; the pre-existing
# desktop carried over from initial.tf with the task applied to it), as the clean witness of the
# main intent with nobody else acting on the account: the design team's cloud desktop running on
# the size the row gives it, backed up every day at midnight by AWS Backup into a vault of its
# own, through a role AWS Backup can assume.
#
# Deviations from the row's reference text, all of them the witness's choice rather than the
# task's:
#   * the image lookup. The row filters `*ubuntu-noble-24.04-amd64-server-*` while asking for
#     `owners = ["amazon"]`; Canonical owns the Ubuntu images, so that pair matches nothing.
#     The account's current image is Amazon Linux 2023, which is what the desktop runs on.
#   * the names. The row calls its resources `cloud_desktop_backup_plan`,
#     `cloud_desktop_backup_valut` and `backup`; this account names a resource after the
#     workload it serves and what it does for it.
#   * the instance. The row launches one; the desktop is already there, at `t3.small`, and what
#     the task changes on it is its size — the row's own `t2.micro`.
# The row's schedule, its `WindowsVSS` advanced backup setting on resource type EC2, its vault,
# its plan rule, its selection over the instance's ARN and the managed policy on the backup role
# are reproduced as the row describes.
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

resource "aws_instance" "cloud_desktop" {
  ami           = data.aws_ami.al2023.id
  instance_type = "t2.micro"

  tags = {
    Name = "cloud-desktop"
    Team = "design"
  }
}

resource "aws_backup_vault" "cloud_desktop" {
  name = "cloud-desktop-backup-vault"
}

resource "aws_backup_plan" "cloud_desktop" {
  name = "cloud-desktop-backup-plan"

  rule {
    rule_name         = "cloud-desktop-daily"
    target_vault_name = aws_backup_vault.cloud_desktop.name
    schedule          = "cron(0 0 * * ? *)"
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
  name               = "cloud-desktop-backup-role"
  assume_role_policy = data.aws_iam_policy_document.backup_assume_role.json
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_backup_selection" "cloud_desktop" {
  name         = "cloud-desktop-backup"
  iam_role_arn = aws_iam_role.backup.arn
  plan_id      = aws_backup_plan.cloud_desktop.id

  resources = [
    aws_instance.cloud_desktop.arn,
  ]
}

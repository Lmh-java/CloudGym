resource "aws_backup_vault" "dependency" {
  name = "cloudgym-capability-selection-vault"
}

resource "aws_backup_plan" "dependency" {
  name = "cloudgym-capability-selection-plan"

  rule {
    rule_name         = "never-in-practice"
    target_vault_name = aws_backup_vault.dependency.name
    schedule          = "cron(0 12 1 1 ? 2035)"
    lifecycle {
      delete_after = 7
    }
  }
}

resource "aws_iam_role" "dependency" {
  name_prefix = "cloudgym-capability-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "dependency" {
  role       = aws_iam_role.dependency.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_backup_selection" "capability" {
  name         = "cloudgym-capability-selection"
  plan_id      = aws_backup_plan.dependency.id
  iam_role_arn = aws_iam_role.dependency.arn

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "cloudgym-backup"
    value = "never-matches"
  }

  depends_on = [aws_iam_role_policy_attachment.dependency]
}

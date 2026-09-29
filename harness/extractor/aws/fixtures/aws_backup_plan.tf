resource "aws_backup_vault" "dependency" {
  name = "cloudgym-capability-plan-vault"
}

resource "aws_backup_plan" "capability" {
  name = "cloudgym-capability-plan"

  rule {
    rule_name         = "never-in-practice"
    target_vault_name = aws_backup_vault.dependency.name
    # A far-future one-off schedule: no backup job (and no billable recovery point) ever runs.
    schedule = "cron(0 12 1 1 ? 2035)"
    lifecycle {
      delete_after = 7
    }
  }
}

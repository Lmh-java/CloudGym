# Vault names are unique per account and region; an empty vault deletes at once, so the
# name is free again as soon as the previous smoke destroyed it.
resource "aws_glacier_vault" "capability" {
  name = "cloudgym-capability-vault"

  tags = {
    Name = "cloudgym-capability"
  }
}

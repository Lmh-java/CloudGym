# Pre-existing: the shared store the account keeps for its inventory reports. The account
# names its stores by serial and not by content (prefix `store-`, account id embedded so
# concurrently deployed arms never collide on the global name); `Store` is the account's
# marking for what a store keeps and `Owner` says whose it is, so what a store holds is read
# off its marks rather than off its name.
#
# Nothing of the task exists yet: at S0 the account holds no store for the orders-team
# application's export objects, no bucket anywhere carries an inventory configuration, this
# store holds no bucket policy at all, it is the only store in the account marked as keeping
# inventory reports, and it declares nothing about where reports sit under it — so nothing
# here satisfies the task or already carries a norm.

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "reports" {
  bucket_prefix = "store-${data.aws_caller_identity.current.account_id}-"
  force_destroy = true

  tags = {
    Store = "inventory-reports"
    Owner = "storage-platform"
  }
}

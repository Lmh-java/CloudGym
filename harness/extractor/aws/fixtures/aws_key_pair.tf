resource "aws_key_pair" "capability" {
  key_name_prefix = "cloudgym-capability-"
  # Throwaway public half of an ed25519 key generated for this fixture; no private key is kept.
  public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDB3SyDPnHBRLmt+wBzhVNGGOOUGoPJP82xcVyN7+nNi cloudgym-capability"
}

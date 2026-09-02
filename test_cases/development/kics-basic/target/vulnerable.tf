resource "aws_s3_bucket_public_access_block" "agent_artifacts" {
  bucket            = "project-sonic-agent-artifacts"
  block_public_acls = false
}

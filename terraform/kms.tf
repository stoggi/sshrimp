data "aws_iam_policy_document" "sshrimp_ca_private_key" {
  // Allow the root account to administer the key, but not encrypt/decrypt/sign
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions = [
      "kms:CancelKeyDeletion",
      "kms:Create*",
      "kms:Delete*",
      "kms:Describe*",
      "kms:Disable*",
      "kms:Enable*",
      "kms:Get*",
      "kms:List*",
      "kms:Put*",
      "kms:Revoke*",
      "kms:ScheduleKeyDeletion",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:Update*",
    ]

    resources = ["*"]
  }

  // Allow the SSHrimp lambda to sign and get the public key
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["${aws_iam_role.sshrimp_ca.arn}"]
    }

    actions = [
      "kms:Sign",
      "kms:GetPublicKey",
    ]

    resources = ["*"]
  }
}


resource "aws_kms_key" "sshrimp_ca_private_key" {
  description              = "KMS key used to sign SSH certificates for the SSHrimp Certificate Authority"
  deletion_window_in_days  = 10
  customer_master_key_spec = "RSA_4096"
  key_usage                = "SIGN_VERIFY"
  policy                   = data.aws_iam_policy_document.sshrimp_ca_private_key.json
  depends_on = [
    aws_iam_role.sshrimp_ca,
  ]
}

resource "aws_kms_alias" "sshrimp_ca_private_key" {
  name          = "alias/${var.key_alias}"
  target_key_id = aws_kms_key.sshrimp_ca_private_key.key_id
}

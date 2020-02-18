
data "aws_iam_policy_document" "sshrimp_ca_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "sshrimp_ca" {
  statement {
    actions = [
      "kms:Sign",
      "kms:GetPublicKey"
    ]
    resources = [
      "${aws_kms_key.sshrimp_ca_private_key.arn}",
    ]
  }

  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "*",
    ]
  }
}


resource "aws_iam_role_policy" "sshrimp_ca" {
  name   = "sshrimp-ca-${data.aws_region.current.name}"
  role   = aws_iam_role.sshrimp_ca.id
  policy = data.aws_iam_policy_document.sshrimp_ca.json
}

resource "aws_iam_role" "sshrimp_ca" {
  name               = "sshrimp-ca-${data.aws_region.current.name}"
  assume_role_policy = data.aws_iam_policy_document.sshrimp_ca_assume_role.json
}

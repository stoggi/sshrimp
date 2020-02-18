
resource "aws_lambda_function" "sshrimp_ca" {
  function_name = var.lambda_name
  filename      = "sshrimp-ca.zip"
  role          = aws_iam_role.sshrimp_ca.arn
  timeout       = 120
  memory_size   = 512
  description   = "SSHrimp Certificate Authority"
  handler       = "sshrimp-ca"
  runtime       = "go1.x"
}

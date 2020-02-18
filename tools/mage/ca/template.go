package ca

import (
	"github.com/awslabs/goformation/v4/cloudformation"
	"github.com/awslabs/goformation/v4/cloudformation/iam"
	"github.com/awslabs/goformation/v4/cloudformation/kms"
	"github.com/awslabs/goformation/v4/cloudformation/lambda"
	"github.com/stoggi/sshrimp/internal/config"
)

func makePolicyDocument(statement map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []interface{}{
			statement,
		},
	}
}

func makeAssumeRolePolicyDocument(service string) map[string]interface{} {
	return makePolicyDocument(map[string]interface{}{
		"Effect": "Allow",
		"Principal": map[string][]string{
			"Service": []string{service},
		},
		"Action": []string{"sts:AssumeRole"},
	})
}

func generateTemplate(c *config.SSHrimp) ([]byte, error) {

	// Create a new CloudFormation template
	template := cloudformation.NewTemplate()

	template.Resources["SSHrimpPrivateKey"] = &kms.Key{
		Description:         "SSHrimp Certificate Authority Private Key",
		PendingWindowInDays: 7,
		KeyUsage:            "SIGN_VERIFY",
		KeyPolicy: makePolicyDocument(map[string]interface{}{
			"Effect": "Allow",
			"Principal": map[string][]string{
				"AWS": []string{
					cloudformation.GetAtt("SSHrimpLambdaExecutionRole", "Arn"),
				},
			},
			"Action": []string{
				"kms:GetPublicKey",
				"kms:Sign",
			},
			"Resource": cloudformation.GetAtt("SSHrimpLambda", "Arn"),
		}),
	}

	template.Resources["SSHrimpLambdaExecutionRole"] = &iam.Role{
		AssumeRolePolicyDocument: makeAssumeRolePolicyDocument("lambda.amazonaws.com"),
		RoleName:                 "sshrimp-ca",
		Policies: []iam.Role_Policy{
			{
				PolicyDocument: makePolicyDocument(map[string]interface{}{
					"Effect":   "Allow",
					"Action":   "kms:Sign",
					"Resource": "*",
				}),
				PolicyName: "sshrimp-ca-lambda",
			},
		},
	}

	template.Resources["SSHrimpLambda"] = &lambda.Function{
		FunctionName: c.CertificateAuthority.FunctionName,
		Description:  "SSHrimp Certificate Authority",
		Role:         cloudformation.GetAtt("SSHrimpLambdaExecutionRole", "Arn"),
		Handler:      "sshrimp-ca",
		MemorySize:   512,
		Runtime:      "python3.7",
		Code: &lambda.Function_Code{
			ZipFile: "sshrimp-ca.zip",
		},
	}

	// Generate the YAML AWS CloudFormation template
	y, err := template.YAML()
	if err != nil {
		return nil, err
	}

	return y, nil
}

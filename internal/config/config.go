package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/BurntSushi/toml"
	"github.com/kballard/go-shellquote"
)

// Agent config for the sshrimp-agent agent
type Agent struct {
	ProviderURL    string
	ClientID       string
	ClientSecret   string
	BrowserCommand []string
	Socket         string
}

// CertificateAuthority config for the sshrimp-ca lambda
type CertificateAuthority struct {
	Project            string
	AccountID          int
	Regions            []string
	FunctionName       string
	KeyAlias           string
	ForceCommandRegex  string
	SourceAddressRegex string
	UsernameRegex      string
	UsernameClaim      string
	ValidAfterOffset   string
	ValidBeforeOffset  string
	Extensions         []string
}

// SSHrimp main configuration struct for sshrimp-agent and sshrimp-ca
type SSHrimp struct {
	Agent                Agent
	CertificateAuthority CertificateAuthority
}

// List of supported regions for the config wizard
var SupportedAwsRegions = []string{
	"ap-east-1",
	"ap-northeast-1",
	"ap-northeast-2",
	"ap-south-1",
	"ap-southeast-1",
	"ap-southeast-2",
	"ca-central-1",
	"eu-central-1",
	"eu-north-1",
	"eu-west-1",
	"eu-west-2",
	"eu-west-3",
	"me-south-1",
	"sa-east-1",
	"us-east-1",
	"us-east-2",
	"us-west-1",
	"us-west-2",
}

var SupportedGcpRegions = []string{
	"europe-west1",
	"europe-west2",
	"europe-west3",
	"us-central1",
	"us-east1",
	"us-east4",
	"asia-northeast1",
	"asia-east2",
}

var supportedExtensions = []string{
	"no-agent-forwarding",
	"no-port-forwarding",
	"no-pty",
	"no-user-rc",
	"no-x11-forwarding",
	"permit-agent-forwarding",
	"permit-port-forwarding",
	"permit-pty",
	"permit-user-rc",
	"permit-x11-forwarding",
}

// NewSSHrimp returns SSHrimp
func NewSSHrimp() *SSHrimp {
	return &SSHrimp{}
}

// NewSSHrimpWithDefaults returns SSHrimp with defaults already set
func NewSSHrimpWithDefaults() *SSHrimp {

	sshrimp := SSHrimp{
		Agent{
			ProviderURL: "https://accounts.google.com",
			Socket:      "/tmp/sshrimp.sock",
		},
		CertificateAuthority{
			FunctionName:       "sshrimp",
			KeyAlias:           "alias/sshrimp",
			ForceCommandRegex:  "^$",
			SourceAddressRegex: "^$",
			UsernameRegex:      `^(.*)@example\.com$`,
			UsernameClaim:      "email",
			ValidAfterOffset:   "-5m",
			ValidBeforeOffset:  "+12h",
			Extensions: []string{
				"permit-agent-forwarding",
				"permit-port-forwarding",
				"permit-pty",
				"permit-user-rc",
				"no-x11-forwarding",
			},
		},
	}
	return &sshrimp
}

// DefaultPath of the sshrimp config file
var DefaultPath = "./sshrimp.toml"

// EnvVarName is the optional environment variable that if set overrides DefaultPath
var EnvVarName = "SSHRIMP_CONFIG"

// GetPath returns the default sshrimp config file path taking into account EnvVarName
func GetPath() string {
	if configPathFromEnv, ok := os.LookupEnv(EnvVarName); ok && configPathFromEnv != "" {
		return configPathFromEnv
	}
	return DefaultPath
}

func validateInt(val interface{}) error {
	if str, ok := val.(string); ok {
		if _, err := strconv.Atoi(str); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("expected type string got %v", reflect.TypeOf(val).Name())
	}

	return nil
}

func validateURL(val interface{}) error {
	if str, ok := val.(string); ok {
		if _, err := url.ParseRequestURI(str); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("expected type string got %v", reflect.TypeOf(val).Name())
	}

	return nil
}

func validateDuration(val interface{}) error {
	if str, ok := val.(string); ok {
		if _, err := time.ParseDuration(str); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("expected type string got %v", reflect.TypeOf(val).Name())
	}

	return nil
}

func validateAlias(val interface{}) error {
	if str, ok := val.(string); ok {
		if !strings.HasPrefix(str, "alias/") {
			return errors.New("KMS alias must begin with alias/")
		}
	} else {
		return fmt.Errorf("expected type string got %v", reflect.TypeOf(val).Name())
	}

	return nil
}

func certificateAuthorityQuestions(config *SSHrimp) []*survey.Question {
	defaultAccountID := ""
	if config.CertificateAuthority.AccountID > 0 {
		defaultAccountID = strconv.Itoa(config.CertificateAuthority.AccountID)
	}
	return []*survey.Question{
		{
			Name: "AccountID",
			Prompt: &survey.Input{
				Message: "AWS Account ID:",
				Default: defaultAccountID,
				Help:    "12 Digit account ID. You could get this by running `aws sts get-caller-identity`",
			},
			Validate: survey.ComposeValidators(
				survey.Required,
				validateInt,
				survey.MaxLength(12),
				survey.MinLength(12),
			),
		},
		{
			Name: "Regions",
			Prompt: &survey.MultiSelect{
				Message:  "AWS Region:",
				Default:  config.CertificateAuthority.Regions,
				Help:     "Select multiple regions for high availability. Each region gets it's own Lambda function and KMS key.",
				Options:  SupportedAwsRegions,
				PageSize: 10,
			},
			Validate: survey.Required,
		},
		{
			Name: "FunctionName",
			Prompt: &survey.Input{
				Message: "Lambda Function Name:",
				Help:    "The sshrimp certificate authority lambda will have this name.",
				Default: config.CertificateAuthority.FunctionName,
			},
			Validate: survey.Required,
		},
		{
			Name: "KeyAlias",
			Prompt: &survey.Input{
				Message: "KMS Key Alias:",
				Help:    "A name beginning with 'alias/' to easily refer to KMS keys in IAM policies and configuration files.",
				Default: config.CertificateAuthority.KeyAlias,
			},
			Validate: survey.ComposeValidators(
				survey.Required,
				validateAlias,
			),
		},
		{
			Name: "UsernameClaim",
			Prompt: &survey.Input{
				Message: "Username claim in JWT",
				Help:    "Which claim in the JWT should be used as the username. See https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims",
				Default: config.CertificateAuthority.UsernameClaim,
			},
			Validate: survey.Required,
		},
		{
			Name: "UsernameRegex",
			Prompt: &survey.Input{
				Message: "Username regular expression",
				Help:    "A regular expression to validate the username present in the identity token. The first matching group will be used as the username enforced in the certificate.",
				Default: config.CertificateAuthority.UsernameRegex,
			},
			Validate: survey.Required,
		},
		{
			Name: "ForceCommandRegex",
			Prompt: &survey.Input{
				Message: "ForceCommand regular expression:",
				Help:    "A regular expression to validate the force command supplied by the user, but enforced in the certificate. See https://man.openbsd.org/sshd_config#ForceCommand",
				Default: config.CertificateAuthority.ForceCommandRegex,
			},
			Validate: survey.Required,
		},
		{
			Name: "SourceAddressRegex",
			Prompt: &survey.Input{
				Message: "Source IP address regular expression",
				Help:    "A regular expression to validate the source IP address supplied by the user, but enforced in the certificate.",
				Default: config.CertificateAuthority.SourceAddressRegex,
			},
			Validate: survey.Required,
		},
		{
			Name: "ValidAfterOffset",
			Prompt: &survey.Input{
				Message: "A time.now() offset for valid_after",
				Help:    "The amount to add to time.now() that the certificate will be valid FROM.",
				Default: config.CertificateAuthority.ValidAfterOffset,
			},
			Validate: survey.ComposeValidators(
				survey.Required,
				validateDuration,
			),
		},
		{
			Name: "ValidBeforeOffset",
			Prompt: &survey.Input{
				Message: "A time.now() offset for valid_before",
				Help:    "The amount to add to time.now() that the certificate will be valid TO.",
				Default: config.CertificateAuthority.ValidBeforeOffset,
			},
			Validate: survey.ComposeValidators(
				survey.Required,
				validateDuration,
			),
		},
		{
			Name: "Extensions",
			Prompt: &survey.MultiSelect{
				Message:  "Certificate extensions",
				Help:     "Extensions to be added to the certificate, see https://man.openbsd.org/ssh-keygen#CERTIFICATES",
				Default:  config.CertificateAuthority.Extensions,
				Options:  supportedExtensions,
				PageSize: 10,
			},
			Validate: survey.Required,
		},
	}
}

func agentQuestions(config *SSHrimp) []*survey.Question {
	return []*survey.Question{
		{
			Name: "ProviderURL",
			Prompt: &survey.Input{
				Message: "OpenIDConnect Provider URL:",
				Default: config.Agent.ProviderURL,
				Help:    "Get this from your OIDC provider. For example Google's is https://accounts.google.com.",
			},
			Validate: survey.ComposeValidators(survey.Required, validateURL),
		},
		{
			Name: "ClientID",
			Prompt: &survey.Input{
				Message: "OpenIDConnect Client ID:",
				Default: config.Agent.ClientID,
				Help:    "Get this from your OIDC provider. For example Google uses the format 1234-0a1b2bc3.apps.googleusercontent.com",
			},
			Validate: survey.Required,
		},
		{
			Name: "ClientSecret",
			Prompt: &survey.Input{
				Message: "OpenIDConnect Client Secret (only if required):",
				Default: config.Agent.ClientSecret,
				Help:    "Google requires the Client Secret even when using PKCE. Most OpenIDConnect provdiders don't. Read more about PKCE: https://tools.ietf.org/html/rfc7636",
			},
		},
		{
			Name: "Socket",
			Prompt: &survey.Input{
				Message: "sshrimp-agent socket:",
				Default: config.Agent.Socket,
				Help:    "Path of the socket for the sshrimp-agent to listen on. Create a unique one for each instance of sshrimp-agent.",
			},
			Validate: survey.Required,
		},
	}
}

func browserCommandQuestions(config *SSHrimp) []*survey.Question {
	return []*survey.Question{
		{
			Name: "BrowserCommand",
			Prompt: &survey.Input{
				Message: "Command to open a browser:",
				Default: shellquote.Join(config.Agent.BrowserCommand...),
				Help:    "Optionally {} will be substituted with the URL to open.",
			},
			Validate: survey.Required,
		},
	}
}

func configFileQuestions(configPath string) []*survey.Question {
	return []*survey.Question{
		{
			Name: "ConfigPath",
			Prompt: &survey.Input{
				Message: "File path to write the new config:",
				Default: configPath,
				Help:    "Set environment variable SSHRIMP_CONFIG to this path if different from ./sshrimp.toml",
			},
			Validate: survey.Required,
		},
	}
}

func (c *SSHrimp) Read(configPath string) error {
	_, err := toml.DecodeFile(configPath, c)
	return err
}

func (c *SSHrimp) Write(configPath string) error {
	// Create the new config file
	configFile, err := os.Create(configPath)
	if err != nil {
		return err
	}
	defer configFile.Close()

	// Encode the configuration values as a TOML file
	encoder := toml.NewEncoder(configFile)
	if err := encoder.Encode(c); err != nil {
		return err
	}

	return nil
}

// Wizard launches a interactive question/answer terminal prompt to create a config file
func Wizard(configPath string, config *SSHrimp) (string, error) {

	// Create a new config that doesn't have any default values, otherwise survey appends to the defaults.
	newConfig := NewSSHrimp()

	if err := survey.Ask(certificateAuthorityQuestions(config), &newConfig.CertificateAuthority); err != nil {
		return "", err
	}

	if err := survey.Ask(agentQuestions(config), &newConfig.Agent); err != nil {
		return "", err
	}

	// Ask BrowserCommand separately so we can store it as a []string, currently not supported by survey.
	var browserCommand string
	if err := survey.Ask(browserCommandQuestions(config), &browserCommand); err != nil {
		return "", err
	}
	// Split the command by sh rules using shellquote. The command is stored as a slice of arguments.
	words, err := shellquote.Split(browserCommand)
	if err != nil {
		return "", err
	}
	newConfig.Agent.BrowserCommand = words

	// Confirm config file path, and keep prompting if exists and user chooses not to overwrite
	var overwriteIfExists = false
	for !overwriteIfExists {
		if err := survey.Ask(configFileQuestions(configPath), &configPath); err != nil {
			return "", err
		}

		if _, err := os.Stat(configPath); err == nil {
			// File exists, confirm to be overwritten
			if err := survey.AskOne(&survey.Confirm{
				Message: "File exists, overwrite?",
				Default: false,
			}, &overwriteIfExists); err != nil {
				return "", err
			}
		} else {
			// File doesn't exist, break and save the file
			break
		}
	}

	// Write the new configuration to a file
	newConfig.Write(configPath)

	return configPath, nil
}

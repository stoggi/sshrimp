# sshrimp 🦐

SSH Certificate Authority in a lambda, automated by an OpenID Connect enabled agent.

Why? Check out this presentation [Zero Trust SSH - linux.conf.au 2020](http://youtu.be/lYzklWPTbsQ).

## ~~ Warning ~~

This is still in very early development. Only use for testing. Not suitable for use in production yet. PR's welcome ;)

## Quickstart

This project uses [mage](https://magefile.org/) as a build tool. Install it.

Build the agent, lambda, and generate terraform code ready for deployment:

    mage

## Deployment

[Terraform](https://www.terraform.io/) files are defined in `/terraform` and the generated `sshrimp-ca.tf.json` file can be used to automatically deploy sshrimp into multiple AWS regions.

    terraform init
    terraform apply

> You will need [AWS credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) in your environment to run `terraform apply`. You can also use [aws-vault](https://github.com/99designs/aws-vault) or [aws-oidc](https://github.com/stoggi/aws-oidc) to more securely manage AWS credentials on the command line.


## sshd_config (on your server)

Server configruation is minimal. Get the public keys from KMS (using AWS credentials):

    mage ca:keys

Put these keys in a file on your server `/etc/ssh/trusted_user_ca_keys`, owned by `root` permissions `0644`.

Modify `/etc/ssh/sshd_config` to add the line:

    TrustedUserCAKeys /etc/ssh/trusted_user_ca_keys


## ssh_config (on your local computer)

Since OpenSSH (>= 7.3), you can use the [IdentityAgent](https://man.openbsd.org/ssh_config.5#IdentityAgent) option in your ssh config file to set the socketname you configured:

    Host *.sshrimp.io
        User jeremy
        IdentityAgent /tmp/sshrimp-agent.sock

This has the advantage of only using the agent for the group of hosts you need, and let other hosts use your regular agent (like github.com for cloning git repos). In fact, you can't add other identities to the sshrimp-agent. It's meant to be used for only the hosts you need it for.

> For other SSH clients or older versions, set the `SSH_AUTH_SOCK` environment variable when invoking ssh: `SSH_AUTH_SOCK=/tmp/sshrimp-agent.sock ssh user@host`

## Let's go!

Start the agent:

    sshrimp-agent /path/to/sshrimp.toml

SSH to your host:

    ssh example.server.sshrimp.io

🎉

## Why sshrimp?

* Shrimp have shells.
* Shrimp are lightweight.
* Has a [backronym](https://en.wikipedia.org/wiki/Backronym): SSH. Really. Isn't. My. Problem.
* Shrimp on a barbie?
* Yeah...

# security-group-manager

[![Release](https://img.shields.io/github/v/release/ReasonSoftware/security-group-manager)](https://github.com/ReasonSoftware/security-group-manager/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/ReasonSoftware/security-group-manager)](https://goreportcard.com/report/github.com/ReasonSoftware/security-group-manager)
[![Release](https://github.com/ReasonSoftware/security-group-manager/workflows/release/badge.svg)](https://github.com/ReasonSoftware/security-group-manager/actions)
[![License](https://img.shields.io/github/license/ReasonSoftware/security-group-manager)](LICENSE.md)

An AWS **Lambda** to maintain whitelist rules on **Security Groups**.

![PIC](docs/images/demo.gif)

## Features

- Manage trusted CIDRs in one place.
- Manage some or all of the rules in a security group automatically.
- Mix multiple protocols on a security group.
- Define your own custom protocols.

## Manual

Tag a security group with `<protocol-name>=managed` that matches of the protocols from a configuration.

## Install

1. Download [latest release](https://github.com/ReasonSoftware/security-group-manager/releases/latest) and extract the archive
2. Create **AWS Secrets Manager** Secret with the sample/custom configuration:

    <details><summary>Sample Configuration</summary>

    ```json
    {
        "protocols": {
            "http": {
                "transport": "tcp",
                "from_port": 80,
                "to_port": 80
            },
            "https": {
                "transport": "tcp",
                "from_port": 443,
                "to_port": 443
            },
            "ssh": {
                "transport": "tcp",
                "from_port": 22,
                "to_port": 22
            },
            "rdp": {
                "transport": "tcp",
                "from_port": 3389,
                "to_port": 3389
            }
        },
        "rules": [
            {
                "cidr": "34.226.14.13/32",
                "note": "Primary VPN"
            },
            {
                "cidr": "52.15.127.128/27",
                "note": "UK Office"
            },
            {
                "cidr": "35.158.136.0/22",
                "note": "US Office"
            },
            {
                "cidr": "52.57.254.0/29",
                "note": "IL Office"
            },
            {
                "cidr": "13.54.63.128/32",
                "note": "Backup VPN"
            }
        ]
    }
    ```

    </details>

3. Update `serverless.yaml`
    - **Secret Name**: Fill in you secret name under `environment/SECRET`
    - **Secrets Manager Permissions**: Update `iamRoleStatements/Resource` to contain your secret name or full ARN.
    - Lambda is configured to run periodically every half an hour, you may change that under `functions/app/schedule`.

    <details><summary>Optional Configuration</summary>

    You may tweak the Lambda's behavior via additional environmental variables:

    - `DEBUG=true` - Enable verbose logs
    - `LOCAL=true` - Toggle to execute outside of AWS Lambda environment (useful during local development)
    - `OPERATIONAL_REGION=<region>` - Region in which lambda should manage the security groups. This allows to manage multiple regions from multiple lambdas deployed in a single region (default: `us-east-1`)
    - `SECRET_REGION=<region>` - **Secrets Manager** region in which a *whitelist* secret is created. Allows to maintain a single *source of truth* for lambdas deployed in multiple regions (default: `us-east-1`)

    </details>

4. Deploy with: `serverless deploy --stage prod` or create Lambda manually

*In order to use latest version (master branch), you may clone the repository and compile the project by running `make release` before deploying it*

## Notes

- You may build the project for `linux/amd64` using `Go` or handy `make` scripts on Linux/MacOS workstation:
  - `make lint` - Lint project
  - `make test` - Execute unit tests
  - `make` - Lint + Unit Test + Vendor
  - `make codecov` - Open code-coverage report
  - `make release` - Compile project

## License

[MIT](LICENSE.md) © 2020 Reason Cybersecurity Ltd.

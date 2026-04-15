package app

import (
	"encoding/json"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/pkg/errors"
)

// GetConfig returns parsed Configuration from AWS Secrets Manager.
// The secret is fetched on every Lambda invocation so IP changes
// propagate within one cron cycle without requiring a redeploy.
func GetConfig(cli Client, secret string) (*Config, error) {
	o, err := cli.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secret),
		VersionStage: aws.String("AWSCURRENT"),
	})
	if err != nil {
		return new(Config), errors.Wrap(err, "error fetching secret")
	}

	c := new(Config)
	if err := json.Unmarshal([]byte(*o.SecretString), c); err != nil {
		return new(Config), errors.Wrap(err, "error parsing secret")
	}

	if len(c.Protocols) == 0 || len(c.Rules) == 0 {
		return new(Config), errors.New("malformed secret")
	}

	return c, nil
}

package app_test

import (
	"testing"

	"github.com/pkg/errors"

	"github.com/ReasonSoftware/security-group-manager/internal/app"
	"github.com/ReasonSoftware/security-group-manager/mocks"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/stretchr/testify/assert"
)

const secret string = "secret"

func TestGetConfig(t *testing.T) {
	assert := assert.New(t)

	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secret),
		VersionStage: aws.String("AWSCURRENT"),
	}

	type test struct {
		MockOutput     *secretsmanager.GetSecretValueOutput
		MockError      error
		ExpectedError  string
		ExpectedOutput *app.Config
	}

	suite := map[string]test{
		"Success": {
			MockOutput: &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String(`{
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
		}
	},
	"rules": [
		{
			"cidr": "10.0.0.0/16",
			"note": "New Jersey Office"
		},
		{
			"cidr": "192.168.0.0/16",
			"note": "London Office"
		}
	]
}`),
			},
			MockError:     nil,
			ExpectedError: "",
			ExpectedOutput: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
					"https": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(443),
						ToPort:    aws.Int64(443),
					},
				},
				Rules: []*app.Rule{
					{CIDR: aws.String("10.0.0.0/16")},
					{CIDR: aws.String("192.168.0.0/16")},
				},
			},
		},
		"Secrets Manager API Failure": {
			MockOutput:     &secretsmanager.GetSecretValueOutput{},
			MockError:      errors.New("reason"),
			ExpectedError:  "error fetching secret: reason",
			ExpectedOutput: &app.Config{},
		},
		"Nil SecretString (binary secret)": {
			MockOutput:     &secretsmanager.GetSecretValueOutput{SecretString: nil},
			MockError:      nil,
			ExpectedError:  "secret has no SecretString payload (binary secrets are not supported)",
			ExpectedOutput: &app.Config{},
		},
		"Invalid JSON": {
			MockOutput: &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String(`{invalid json`),
			},
			MockError:      nil,
			ExpectedError:  "error parsing secret: invalid character 'i' looking for beginning of object key string",
			ExpectedOutput: &app.Config{},
		},
		"Empty Protocols Section": {
			MockOutput: &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String(`{"rules":[{"cidr":"10.0.0.0/16"}]}`),
			},
			MockError:      nil,
			ExpectedError:  "malformed secret",
			ExpectedOutput: &app.Config{},
		},
		"Empty Rules Section": {
			MockOutput: &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String(`{"protocols":{"http":{"transport":"tcp","from_port":80,"to_port":80}}}`),
			},
			MockError:      nil,
			ExpectedError:  "malformed secret",
			ExpectedOutput: &app.Config{},
		},
	}

	var counter int
	for name, tc := range suite {
		counter++
		t.Logf("Test Case %v/%v - %s", counter, len(suite), name)

		m := new(mocks.SM)
		m.On("GetSecretValue", input).Return(tc.MockOutput, tc.MockError).Once()

		result, err := app.GetConfig(m, secret)

		if tc.ExpectedError != "" {
			assert.EqualError(err, tc.ExpectedError)
		} else {
			assert.NoError(err)
		}

		assert.Equal(tc.ExpectedOutput, result)
	}
}

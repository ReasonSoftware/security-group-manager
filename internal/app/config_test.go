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

	type test struct {
		Parameter      string
		MockInput      *secretsmanager.GetSecretValueInput
		MockOutput     *secretsmanager.GetSecretValueOutput
		MockError      error
		ExpectedError  string
		ExpectedOutput *app.Config
	}

	suite := map[string]test{
		"Success": {
			Parameter: secret,
			MockInput: &secretsmanager.GetSecretValueInput{
				SecretId:     aws.String(secret),
				VersionStage: aws.String("AWSCURRENT"),
			},
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
		"Failure": {
			Parameter: secret,
			MockInput: &secretsmanager.GetSecretValueInput{
				SecretId:     aws.String(secret),
				VersionStage: aws.String("AWSCURRENT"),
			},
			MockOutput:     &secretsmanager.GetSecretValueOutput{},
			MockError:      errors.New("reason"),
			ExpectedError:  "error fetching secret: reason",
			ExpectedOutput: &app.Config{},
		},
	}

	var counter int
	for name, tc := range suite {
		counter++
		t.Logf("Test Case %v/%v - %s", counter, len(suite), name)

		m := new(mocks.SM)
		m.On("GetSecretValue", tc.MockInput).Return(tc.MockOutput, tc.MockError).Once()

		result, err := app.GetConfig(m, tc.Parameter)

		if tc.ExpectedError != "" {
			assert.EqualError(err, tc.ExpectedError)
		} else {
			assert.NoError(err)
		}

		assert.Equal(tc.ExpectedOutput, result)
	}
}

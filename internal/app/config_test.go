package app_test

import (
	"testing"

	"github.com/ReasonSoftware/security-group-manager/internal/app"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
)

func TestGetConfig(t *testing.T) {
	assert := assert.New(t)

	type test struct {
		Config         string
		ExpectedError  string
		ExpectedOutput *app.Config
	}

	suite := map[string]test{
		"Success": {
			Config: `{
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
}`,
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
		"Missing CONFIG": {
			Config:         "",
			ExpectedError:  "CONFIG environment variable is required",
			ExpectedOutput: &app.Config{},
		},
		"Invalid JSON": {
			Config:         `{"protocols":}`,
			ExpectedError:  "error parsing CONFIG: invalid character '}' looking for beginning of value",
			ExpectedOutput: &app.Config{},
		},
		"Empty Protocols Section": {
			Config: `{
	"rules": [
		{"cidr": "10.0.0.0/16"}
	]
}`,
			ExpectedError:  "malformed configuration",
			ExpectedOutput: &app.Config{},
		},
		"Empty Rules Section": {
			Config: `{
	"protocols": {
		"http": {"transport": "tcp", "from_port": 80, "to_port": 80}
	}
}`,
			ExpectedError:  "malformed configuration",
			ExpectedOutput: &app.Config{},
		},
	}

	var counter int
	for name, tc := range suite {
		counter++
		t.Logf("Test Case %v/%v - %s", counter, len(suite), name)

		t.Setenv("CONFIG", tc.Config)

		result, err := app.GetConfig()

		if tc.ExpectedError != "" {
			assert.EqualError(err, tc.ExpectedError)
		} else {
			assert.NoError(err)
		}

		assert.Equal(tc.ExpectedOutput, result)
	}
}

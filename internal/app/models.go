package app

import "github.com/aws/aws-sdk-go/service/secretsmanager"

// TagProtocolValue should match this value in order to indicate that
// a certain protocol should be managed on tagged security group.
// In any case, only "owned" rules will be managed.
const TagProtocolValue = "managed"

// RuleDescription should match this value in order to indicate that
// a certain rule should be managed on security group.
const RuleDescription = "owned"

// Config defines a configuration
// Protocol name should be an AWS Support Application Protocol
type Config struct {
	Protocols map[string]*Protocol `json:"protocols"`
	Rules     []*Rule              `json:"rules"`
}

// Protocol represends a single protocol configuration
type Protocol struct {
	Transport *string `json:"transport"`
	FromPort  *int64  `json:"from_port"`
	ToPort    *int64  `json:"to_port"`
}

// Rule represents a whitelisted CIDR
type Rule struct {
	CIDR *string `json:"cidr"`
}

// Client represents a Secrets Manager client
type Client interface {
	GetSecretValue(*secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error)
}

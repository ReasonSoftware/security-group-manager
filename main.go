package main

import (
	"context"
	"os"
	"strings"

	"github.com/ReasonSoftware/security-group-manager/internal/app"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/sirupsen/logrus"
)

const Version string = "1.1.4"

// Cli is an authorized EC2 Client
var Cli *ec2.EC2

// SCli is an authorized Secrets Manager Client
var SCli *secretsmanager.SecretsManager

// Secret contains the name of the AWS Secrets Manager secret with runtime config
var Secret string

func init() {
	logrus.SetReportCaller(false)
	logrus.SetFormatter(&logrus.JSONFormatter{
		DisableTimestamp: true,
	})
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(parseLogLevel(os.Getenv("LOG_LEVEL")))

	ec2Region := os.Getenv("OPERATIONAL_REGION")
	if ec2Region == "" {
		ec2Region = "us-east-1"
		logrus.Warn("env.var 'OPERATIONAL_REGION' is not set, assuming 'us-east-1'")
	}

	smRegion := os.Getenv("SECRET_REGION")
	if smRegion == "" {
		smRegion = "us-east-1"
		logrus.Warn("env.var 'SECRET_REGION' is not set, assuming 'us-east-1'")
	}

	Secret = os.Getenv("SECRET")
	if Secret == "" {
		logrus.Fatal("SECRET environment variable is required")
	}

	Cli = ec2.New(session.Must(session.NewSession(&aws.Config{
		Region: &ec2Region,
	})))
	SCli = secretsmanager.New(session.Must(session.NewSession(&aws.Config{
		Region: &smRegion,
	})))
}

func parseLogLevel(level string) logrus.Level {
	switch strings.ToLower(level) {
	case "debug":
		return logrus.DebugLevel
	case "warn", "warning":
		return logrus.WarnLevel
	case "error":
		return logrus.ErrorLevel
	default:
		return logrus.InfoLevel
	}
}

func handler(ctx context.Context) error {
	log := logrus.WithField("version", Version)
	log.Info("starting")

	config, err := app.GetConfig(SCli, Secret)
	if err != nil {
		log.WithError(err).Error("error fetching configuration")
		return err
	}

	if err := config.Run(Cli); err != nil {
		log.WithError(err).Error("config run failed")
		return err
	}

	log.Info("finished")

	return nil
}

func main() {
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" {
		lambda.Start(handler)
	} else {
		if err := handler(context.Background()); err != nil {
			logrus.WithError(err).Fatal("handler failed")
		}
	}
}

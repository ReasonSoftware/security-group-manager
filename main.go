package main

import (
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	log "github.com/sirupsen/logrus"

	"github.com/ReasonSoftware/security-group-manager/internal/app"
)

// Cli is an authorized EC2 Client
var Cli *ec2.EC2

// SCli is an authorized Secrets Run Client
var SCli *secretsmanager.SecretsManager

// Config contains parsed configuration
var Config *app.Config

// Secret contains a name of an aws secret containing a runtime config
var Secret string

func init() {
	// define logger
	log.SetReportCaller(false)
	log.SetFormatter(&log.TextFormatter{
		ForceColors:            false,
		FullTimestamp:          true,
		DisableLevelTruncation: true,
		DisableTimestamp:       true,
	})
	log.SetOutput(os.Stdout)
	if strings.ToLower(os.Getenv("DEBUG")) == "true" {
		log.SetLevel(log.DebugLevel)
		log.Warn("starting in debug mode")
	} else {
		log.SetLevel(log.InfoLevel)
	}

	// validate input
	ec2Region := "us-east-1"
	smRegion := "us-east-1"
	if os.Getenv("OPERATIONAL_REGION") != "" {
		ec2Region = os.Getenv("OPERATIONAL_REGION")
	} else {
		log.Warn("env.var 'OPERATIONAL_REGION' is not set, assuming 'us-east-1'")
	}

	if os.Getenv("SECRET_REGION") != "" {
		smRegion = os.Getenv("SECRET_REGION")
	} else {
		log.Warn("env.var 'SECRET_REGION' is not set, assuming 'us-east-1'")
	}

	if os.Getenv("SECRET") == "" {
		log.Fatal("missing aws secret name with configuration")
	}

	Secret = os.Getenv("SECRET")

	// define clients
	Cli = ec2.New(session.Must(session.NewSession(&aws.Config{
		Region: &ec2Region,
	})))
	SCli = secretsmanager.New(session.Must(session.NewSession(&aws.Config{
		Region: &smRegion,
	})))

	// get initial config
	log.Debug("fetching configuration")
	var err error
	Config, err = app.GetConfig(SCli, Secret)
	if err != nil {
		log.Fatal(err)
	}
}

func handler() {
	log.Infof("security-group-manager v%v", app.Version)

	if err := Config.Run(Cli); err != nil {
		log.Fatal(err)
	}

	log.Info("security-group-manager finished")
}

func main() {
	if strings.ToLower(os.Getenv("LOCAL")) == "true" {
		handler()
	} else {
		lambda.Start(handler)
	}
}

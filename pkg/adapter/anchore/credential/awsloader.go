package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	log "github.com/sirupsen/logrus"
)

type AWSCredenitalLoader struct{}

func (c *AWSCredenitalLoader) LoadFromCredentialStore(passwordConfig string) string {
	if strings.HasPrefix(passwordConfig, "aws:secretmanager") {
		log.Debug("Start to load password from AWS Secret Manager")
		value := getAWSSecret(passwordConfig)
		if value != "" {
			return value
		}
	}
	return passwordConfig
}

func getAWSSecret(configValue string) string {
	// The expected format is aws:secretmanager:<region>:<secret name>:<secret key>
	fields := strings.Split(configValue, ":")
	if len(fields) != 5 || fields[0] != "aws" || fields[1] != "secretmanager" {
		log.WithFields(log.Fields{"configValue": configValue}).Error("invalid AWS Secret Manager configuration format")
		return ""
	}
	region, name, key := fields[2], fields[3], fields[4]

	log.WithFields(log.Fields{"region": region, "name": name, "key": key}).Debug("pass in secret manager parameters")

	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("failed to load aws config")
		return ""
	}

	svc := secretsmanager.NewFromConfig(cfg)
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(name),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	result, err := svc.GetSecretValue(ctx, input)
	if err != nil {
		fmt.Println("Secrets Manager error", err)
		log.WithFields(log.Fields{"err": err}).Error("failed to get secret value")
	}

	// Decrypts secret using the associated KMS CMK.
	var secretString string
	if result.SecretString != nil {
		secretString = *result.SecretString
		// a map container to decode the JSON structure into
		kmap := make(map[string]string)
		if err = json.Unmarshal([]byte(secretString), &kmap); err != nil {
			log.WithFields(log.Fields{"err": err}).Error("failed to unmarshal secret string")
			return ""
		}
		return kmap[key]
	}

	return ""
}

package credential

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
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
	fileds := strings.Split(configValue, ":")
	region, name, key := fileds[2], fileds[3], fileds[4]

	log.WithFields(log.Fields{"region": region, "name": name, "key": key}).Debug("pass in secret manager parameters")

	// Create a Secrets Manager client
	awsSession, err := session.NewSession()
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("failed to create aws session")
		return ""
	}
	svc := secretsmanager.New(awsSession, &aws.Config{Region: aws.String(region)})
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(name),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	result, err := svc.GetSecretValue(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok { //nolint:errorlint
			switch aerr.Code() {
			case secretsmanager.ErrCodeDecryptionFailure:
				// Secrets Manager can't decrypt the protected secret text using the provided KMS key.
				fmt.Println(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())

			case secretsmanager.ErrCodeInternalServiceError:
				// An error occurred on the server side.
				fmt.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())

			case secretsmanager.ErrCodeInvalidParameterException:
				// You provided an invalid value for a parameter.
				fmt.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())

			case secretsmanager.ErrCodeInvalidRequestException:
				// You provided a parameter value that is not valid for the current state of the resource.
				fmt.Println(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())

			case secretsmanager.ErrCodeResourceNotFoundException:
				// We can't find the resource that you asked for.
				fmt.Println(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
		}
	} else {
		// Decrypts secret using the associated KMS CMK.
		var secretString string
		if result.SecretString != nil {
			secretString = *result.SecretString
			// a map container to decode the JSON structure into
			kmap := make(map[string]string)
			err := json.Unmarshal([]byte(secretString), &kmap)
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Error("failed to unmarshal secret string")
				return ""
			}
			return kmap[key]
		}
	}

	return ""
}

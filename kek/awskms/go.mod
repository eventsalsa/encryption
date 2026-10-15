module github.com/eventsalsa/encryption/kek/awskms

go 1.26.0

require (
	github.com/aws/aws-sdk-go-v2/service/kms v1.41.0
	github.com/eventsalsa/encryption v0.0.0
)

require (
	github.com/aws/aws-sdk-go-v2 v1.36.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.35 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.35 // indirect
	github.com/aws/smithy-go v1.22.2 // indirect
)

replace github.com/eventsalsa/encryption => ../..

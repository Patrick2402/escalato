package aws

import (
    "context"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/iam"
    // "escalato/internal/models"
)

type Client struct {
    IAMClient *iam.Client
    // Pamięć podręczna dla polityk zarządzanych
    ManagedPoliciesCache map[string]string
}

func NewClient(ctx context.Context, profile, region string) (*Client, error) {
    var opts []func(*config.LoadOptions) error

    if region != "" {
        opts = append(opts, config.WithRegion(region))
    }

    if profile != "" {
        opts = append(opts, config.WithSharedConfigProfile(profile))
    }

    cfg, err := config.LoadDefaultConfig(ctx, opts...)
    if err != nil {
        return nil, err
    }

    iamClient := iam.NewFromConfig(cfg)

    return &Client{
        IAMClient: iamClient,
        ManagedPoliciesCache: make(map[string]string),
    }, nil
}
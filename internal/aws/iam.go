package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"escalato/internal/models"
)


func GetIAMUsers(ctx context.Context, svc *iam.Client, 
	showAccessKeys, showPolicies, showGroups, showDetails bool) ([]models.User, error) {
	
	var users []models.User
	var nextMarker *string

	if showDetails {
		showAccessKeys = true
		showPolicies = true
		showGroups = true
	}


	for {
		listUsersOutput, err := svc.ListUsers(ctx, &iam.ListUsersInput{
			Marker: nextMarker,
		})
		if err != nil {
			return nil, fmt.Errorf("error listing users: %v", err)
		}

		for _, u := range listUsersOutput.Users {

			user := models.User{
				UserName:   *u.UserName,
				UserId:     *u.UserId,
				Arn:        *u.Arn,
				Path:       *u.Path,
				CreateDate: *u.CreateDate,
			}

			if showGroups {
				groupsOutput, err := svc.ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{
					UserName: u.UserName,
				})
				if err == nil {
					for _, group := range groupsOutput.Groups {
						user.Groups = append(user.Groups, *group.GroupName)
					}
				}
			}
			if showPolicies {
				policiesOutput, err := svc.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
					UserName: u.UserName,
				})
				if err == nil {
					for _, policyName := range policiesOutput.PolicyNames {
						user.Policies = append(user.Policies, models.Policy{
							Name: policyName,
							Type: "Inline",
						})
					}
				}

				attachedPoliciesOutput, err := svc.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
					UserName: u.UserName,
				})
				if err == nil {
					for _, policy := range attachedPoliciesOutput.AttachedPolicies {
						user.Policies = append(user.Policies, models.Policy{
							Name: *policy.PolicyName,
							Type: "Managed",
							Arn:  *policy.PolicyArn,
						})
					}
				}
			}
			if showAccessKeys {
				keysOutput, err := svc.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
					UserName: u.UserName,
				})
				if err == nil {
					for _, key := range keysOutput.AccessKeyMetadata {
						accessKey := models.AccessKey{
							Id:         *key.AccessKeyId,
							Status:     string(key.Status),
							CreateDate: *key.CreateDate,
						}

						keyLastUsed, err := svc.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
							AccessKeyId: key.AccessKeyId,
						})
						if err == nil && keyLastUsed.AccessKeyLastUsed != nil && keyLastUsed.AccessKeyLastUsed.LastUsedDate != nil {
							accessKey.LastUsed = &models.LastUsed{
								Date: *keyLastUsed.AccessKeyLastUsed.LastUsedDate,
							}
							
							if keyLastUsed.AccessKeyLastUsed.Region != nil {
								accessKey.LastUsed.Region = *keyLastUsed.AccessKeyLastUsed.Region
							}
							
							if keyLastUsed.AccessKeyLastUsed.ServiceName != nil {
								accessKey.LastUsed.ServiceName = *keyLastUsed.AccessKeyLastUsed.ServiceName
							}
						}

						user.AccessKeys = append(user.AccessKeys, accessKey)
					}
				}
			}

			users = append(users, user)
		}

		if listUsersOutput.IsTruncated {
			nextMarker = listUsersOutput.Marker
		} else {
			break
		}
	}

	return users, nil
}

func GetIAMRoles(ctx context.Context, svc *iam.Client, 
	showPolicies, showTrusted, showLastActivity bool) ([]models.Role, error) {
	
	var roles []models.Role
	var nextMarker *string

	for {
		listRolesOutput, err := svc.ListRoles(ctx, &iam.ListRolesInput{
			Marker: nextMarker,
		})
		if err != nil {
			return nil, fmt.Errorf("error - listing roles: %v", err)
		}

		for _, r := range listRolesOutput.Roles {

			role := models.Role{
				RoleName:   *r.RoleName,
				RoleId:     *r.RoleId,
				Arn:        *r.Arn,
				Path:       *r.Path,
				CreateDate: *r.CreateDate,
			}
			

			if showLastActivity {
				getRoleOutput, err := svc.GetRole(ctx, &iam.GetRoleInput{
					RoleName: r.RoleName,
				})
				
				if err == nil && getRoleOutput.Role.RoleLastUsed != nil {
					if getRoleOutput.Role.RoleLastUsed.LastUsedDate != nil {
						lastUsed := models.RoleLastUsed{
							Date: *getRoleOutput.Role.RoleLastUsed.LastUsedDate,
						}
						
						if getRoleOutput.Role.RoleLastUsed.Region != nil {
							lastUsed.Region = *getRoleOutput.Role.RoleLastUsed.Region
						}
						
						role.LastUsed = &lastUsed
					}
				}
			}

			if showTrusted && r.AssumeRolePolicyDocument != nil {
				document, err := decodePolicy(*r.AssumeRolePolicyDocument)
				if err == nil {
					role.TrustPolicy = document
				}
			}

			if showPolicies {
				policiesOutput, err := svc.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
					RoleName: r.RoleName,
				})
				if err == nil {
					for _, policyName := range policiesOutput.PolicyNames {
						role.Policies = append(role.Policies, models.Policy{
							Name: policyName,
							Type: "Inline",
						})
					}
				}

				attachedPoliciesOutput, err := svc.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
					RoleName: r.RoleName,
				})
				if err == nil {
					for _, policy := range attachedPoliciesOutput.AttachedPolicies {
						role.Policies = append(role.Policies, models.Policy{
							Name: *policy.PolicyName,
							Type: "Managed",
							Arn:  *policy.PolicyArn,
						})
					}
				}
			}

			roles = append(roles, role)
		}

		if listRolesOutput.IsTruncated {
			nextMarker = listRolesOutput.Marker
		} else {
			break
		}
	}

	return roles, nil
}

func decodePolicy(policyDocument string) (string, error) {
	var policy interface{}
	
	if err := json.Unmarshal([]byte(policyDocument), &policy); err != nil {
		return "", err
	}
	
	pretty, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return "", err
	}
	
	return string(pretty), nil
}
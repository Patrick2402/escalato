package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"escalato/internal/models"
)

var (
	EnableDiagnostics = false
)


func logDiagnostic(format string, args ...interface{}) {
	if EnableDiagnostics {
		fmt.Fprintf(os.Stderr, "[DIAG] "+format+"\n", args...)
	}
}

func GetIAMUsers(ctx context.Context, svc *iam.Client, 
	showAccessKeys, showPolicies, showGroups, showDetails bool) ([]models.User, error) {
	
	var users []models.User
	var nextMarker *string

	if showDetails {
		showAccessKeys = true
		showPolicies = true
		showGroups = true
	}

	logDiagnostic("Fetching IAM users with options: accessKeys=%v, policies=%v, groups=%v, details=%v", 
		showAccessKeys, showPolicies, showGroups, showDetails)

	for {
		listUsersOutput, err := svc.ListUsers(ctx, &iam.ListUsersInput{
			Marker: nextMarker,
		})
		if err != nil {
			return nil, fmt.Errorf("error listing users: %v", err)
		}

		logDiagnostic("Retrieved %d users", len(listUsersOutput.Users))

		for _, u := range listUsersOutput.Users {
			logDiagnostic("Processing user: %s", *u.UserName)

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
					logDiagnostic("User %s belongs to %d groups", *u.UserName, len(groupsOutput.Groups))
				} else {
					logDiagnostic("Error fetching groups for user %s: %v", *u.UserName, err)
				}
			}
			
			if showPolicies {
				logDiagnostic("Fetching inline policies for user %s", *u.UserName)
				policiesOutput, err := svc.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
					UserName: u.UserName,
				})
				if err == nil {
					logDiagnostic("User %s has %d inline policies", *u.UserName, len(policiesOutput.PolicyNames))
					for _, policyName := range policiesOutput.PolicyNames {
						// download  inline policies
						logDiagnostic("Fetching policy document for %s", policyName)
						policyOutput, err := svc.GetUserPolicy(ctx, &iam.GetUserPolicyInput{
							UserName:   u.UserName,
							PolicyName: &policyName,
						})
						
						policy := models.Policy{
							Name: policyName,
							Type: "Inline",
						}
						
						if err == nil && policyOutput.PolicyDocument != nil {
							decodedPolicy, err := decodePolicy(*policyOutput.PolicyDocument)
							if err == nil {
								policy.Document = decodedPolicy
								logDiagnostic("Successfully decoded policy %s for user %s (length: %d chars)", 
									policyName, *u.UserName, len(decodedPolicy))
							} else {
								logDiagnostic("Error decoding policy document %s for user %s: %v", 
									policyName, *u.UserName, err)
							}
						} else {
							if err != nil {
								logDiagnostic("Error getting user policy %s for user %s: %v", 
									policyName, *u.UserName, err)
							} else {
								logDiagnostic("Empty policy document for user %s, policy %s", 
									*u.UserName, policyName)
							}
						}
						
						user.Policies = append(user.Policies, policy)
					}
				} else {
					logDiagnostic("Error listing inline policies for user %s: %v", *u.UserName, err)
				}

				logDiagnostic("Fetching attached policies for user %s", *u.UserName)
				attachedPoliciesOutput, err := svc.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
					UserName: u.UserName,
				})
				if err == nil {
					logDiagnostic("User %s has %d attached policies", *u.UserName, len(attachedPoliciesOutput.AttachedPolicies))
					for _, policy := range attachedPoliciesOutput.AttachedPolicies {
						user.Policies = append(user.Policies, models.Policy{
							Name: *policy.PolicyName,
							Type: "Managed",
							Arn:  *policy.PolicyArn,
						})
					}
				} else {
					logDiagnostic("Error listing attached policies for user %s: %v", *u.UserName, err)
				}
			}
			
			if showAccessKeys {
				logDiagnostic("Fetching access keys for user %s", *u.UserName)
				keysOutput, err := svc.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
					UserName: u.UserName,
				})
				if err == nil {
					logDiagnostic("User %s has %d access keys", *u.UserName, len(keysOutput.AccessKeyMetadata))
					for _, key := range keysOutput.AccessKeyMetadata {
						accessKey := models.AccessKey{
							Id:         *key.AccessKeyId,
							Status:     string(key.Status),
							CreateDate: *key.CreateDate,
						}

						logDiagnostic("Fetching last used info for access key %s", *key.AccessKeyId)
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
							
							logDiagnostic("Access key %s was last used on %v", 
								*key.AccessKeyId, *keyLastUsed.AccessKeyLastUsed.LastUsedDate)
						} else {
							if err != nil {
								logDiagnostic("Error getting last used for access key %s: %v", 
									*key.AccessKeyId, err)
							} else {
								logDiagnostic("Access key %s has never been used", *key.AccessKeyId)
							}
						}

						user.AccessKeys = append(user.AccessKeys, accessKey)
					}
				} else {
					logDiagnostic("Error listing access keys for user %s: %v", *u.UserName, err)
				}
			}

			users = append(users, user)
		}

		if listUsersOutput.IsTruncated {
			nextMarker = listUsersOutput.Marker
			logDiagnostic("More users to fetch, continuing with marker")
		} else {
			logDiagnostic("Finished fetching all users")
			break
		}
	}

	return users, nil
}

func GetIAMRoles(ctx context.Context, svc *iam.Client, 
	showPolicies, showTrusted, showLastActivity bool) ([]models.Role, error) {
	
	var roles []models.Role
	var nextMarker *string

	logDiagnostic("Fetching IAM roles with options: policies=%v, trusted=%v, lastActivity=%v", 
		showPolicies, showTrusted, showLastActivity)

	for {
		listRolesOutput, err := svc.ListRoles(ctx, &iam.ListRolesInput{
			Marker: nextMarker,
		})
		if err != nil {
			return nil, fmt.Errorf("error - listing roles: %v", err)
		}

		logDiagnostic("Retrieved %d roles", len(listRolesOutput.Roles))

		for _, r := range listRolesOutput.Roles {
			logDiagnostic("Processing role: %s", *r.RoleName)

			role := models.Role{
				RoleName:   *r.RoleName,
				RoleId:     *r.RoleId,
				Arn:        *r.Arn,
				Path:       *r.Path,
				CreateDate: *r.CreateDate,
			}
			
			if showLastActivity {
				logDiagnostic("Fetching last activity for role %s", *r.RoleName)
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
						
						logDiagnostic("Role %s was last used on %v in region %s", 
							*r.RoleName, *getRoleOutput.Role.RoleLastUsed.LastUsedDate, 
							lastUsed.Region)
					} else {
						logDiagnostic("Role %s has last used info but no date", *r.RoleName)
					}
				} else {
					if err != nil {
						logDiagnostic("Error getting last used for role %s: %v", *r.RoleName, err)
					} else {
						logDiagnostic("Role %s has never been used", *r.RoleName)
					}
				}
			}

			if showTrusted && r.AssumeRolePolicyDocument != nil {
				logDiagnostic("Decoding trust policy for role %s", *r.RoleName)
				document, err := decodePolicy(*r.AssumeRolePolicyDocument)
				if err == nil {
					role.TrustPolicy = document
					logDiagnostic("Successfully decoded trust policy for role %s (length: %d chars)", 
						*r.RoleName, len(document))
				} else {
					logDiagnostic("Error decoding trust policy for role %s: %v", *r.RoleName, err)
				}
			}

			if showPolicies {
				logDiagnostic("Fetching inline policies for role %s", *r.RoleName)
				policiesOutput, err := svc.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
					RoleName: r.RoleName,
				})
				if err == nil {
					logDiagnostic("Role %s has %d inline policies", *r.RoleName, len(policiesOutput.PolicyNames))
					for _, policyName := range policiesOutput.PolicyNames {
						// Pobierz dokument polityki inline
						logDiagnostic("Fetching policy document for %s", policyName)
						policyOutput, err := svc.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
							RoleName:   r.RoleName,
							PolicyName: &policyName,
						})
						
						policy := models.Policy{
							Name: policyName,
							Type: "Inline",
						}
						
						if err == nil && policyOutput.PolicyDocument != nil {
							// Dekoduj dokument polityki
							decodedPolicy, err := decodePolicy(*policyOutput.PolicyDocument)
							if err == nil {
								policy.Document = decodedPolicy
								logDiagnostic("Successfully decoded policy %s for role %s (length: %d chars)", 
									policyName, *r.RoleName, len(decodedPolicy))
							} else {
								logDiagnostic("Error decoding policy document %s for role %s: %v", 
									policyName, *r.RoleName, err)
							}
						} else {
							if err != nil {
								logDiagnostic("Error getting role policy %s for role %s: %v", 
									policyName, *r.RoleName, err)
							} else {
								logDiagnostic("Empty policy document for role %s, policy %s", 
									*r.RoleName, policyName)
							}
						}
						
						role.Policies = append(role.Policies, policy)
					}
				} else {
					logDiagnostic("Error listing inline policies for role %s: %v", *r.RoleName, err)
				}

				logDiagnostic("Fetching attached policies for role %s", *r.RoleName)
				attachedPoliciesOutput, err := svc.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
					RoleName: r.RoleName,
				})
				if err == nil {
					logDiagnostic("Role %s has %d attached policies", *r.RoleName, len(attachedPoliciesOutput.AttachedPolicies))
					for _, policy := range attachedPoliciesOutput.AttachedPolicies {
						role.Policies = append(role.Policies, models.Policy{
							Name: *policy.PolicyName,
							Type: "Managed",
							Arn:  *policy.PolicyArn,
						})
					}
				} else {
					logDiagnostic("Error listing attached policies for role %s: %v", *r.RoleName, err)
				}
			}

			roles = append(roles, role)
		}

		if listRolesOutput.IsTruncated {
			nextMarker = listRolesOutput.Marker
			logDiagnostic("More roles to fetch, continuing with marker")
		} else {
			logDiagnostic("Finished fetching all roles")
			break
		}
	}

	return roles, nil
}

func (c *Client) GetManagedPolicyDocument(ctx context.Context, policyArn string) (string, error) {
    // Sprawdź, czy mamy już tę politykę w pamięci podręcznej
    if doc, ok := c.ManagedPoliciesCache[policyArn]; ok {
        logDiagnostic("Retrieved policy document for %s from cache", policyArn)
        return doc, nil
    }

    logDiagnostic("Fetching managed policy document for %s", policyArn)
    
    // Pobierz informacje o polityce
    policyOutput, err := c.IAMClient.GetPolicy(ctx, &iam.GetPolicyInput{
        PolicyArn: &policyArn,
    })
    
    if err != nil {
        logDiagnostic("Error getting policy %s: %v", policyArn, err)
        return "", err
    }
    
    if policyOutput.Policy == nil || policyOutput.Policy.DefaultVersionId == nil {
        logDiagnostic("Policy or DefaultVersionId is nil for %s", policyArn)
        return "", fmt.Errorf("policy or default version ID is nil")
    }
    
    // Pobierz wersję polityki zawierającą dokument
    versionOutput, err := c.IAMClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
        PolicyArn: &policyArn,
        VersionId: policyOutput.Policy.DefaultVersionId,
    })
    
    if err != nil {
        logDiagnostic("Error getting policy version for %s: %v", policyArn, err)
        return "", err
    }
    
    if versionOutput.PolicyVersion == nil || versionOutput.PolicyVersion.Document == nil {
        logDiagnostic("PolicyVersion or Document is nil for %s", policyArn)
        return "", fmt.Errorf("policy version or document is nil")
    }
    
    // Odkoduj dokument polityki (jest zakodowany URL)
    document, err := decodePolicy(*versionOutput.PolicyVersion.Document)
    if err != nil {
        logDiagnostic("Error decoding policy document for %s: %v", policyArn, err)
        return "", err
    }
    
    logDiagnostic("Successfully fetched policy document for %s (length: %d)", 
        policyArn, len(document))
    
    // Zapisz w pamięci podręcznej
    c.ManagedPoliciesCache[policyArn] = document
    
    return document, nil
}

func (c *Client) UpdateRolePoliciesWithDocuments(ctx context.Context, role *models.Role) error {
    for i, policy := range role.Policies {
        // Jeśli to polityka zarządzana i nie ma jeszcze dokumentu, pobierz go
        if policy.Type == "Managed" && policy.Document == "" && policy.Arn != "" {
            logDiagnostic("Fetching document for managed policy %s (ARN: %s) for role %s", 
                policy.Name, policy.Arn, role.RoleName)
            
            document, err := c.GetManagedPolicyDocument(ctx, policy.Arn)
            if err != nil {
                logDiagnostic("Failed to fetch managed policy document for %s: %v", policy.Arn, err)
                continue
            }
            
            // Zaktualizuj dokument polityki
            role.Policies[i].Document = document
            logDiagnostic("Updated managed policy document for %s", policy.Name)
        }
    }
    
    return nil
}


func (c *Client) UpdateUserPoliciesWithDocuments(ctx context.Context, user *models.User) error {
    for i, policy := range user.Policies {
        // Jeśli to polityka zarządzana i nie ma jeszcze dokumentu, pobierz go
        if policy.Type == "Managed" && policy.Document == "" && policy.Arn != "" {
            logDiagnostic("Fetching document for managed policy %s (ARN: %s) for user %s", 
                policy.Name, policy.Arn, user.UserName)
            
            document, err := c.GetManagedPolicyDocument(ctx, policy.Arn)
            if err != nil {
                logDiagnostic("Failed to fetch managed policy document for %s: %v", policy.Arn, err)
                continue
            }
            
            // Zaktualizuj dokument polityki
            user.Policies[i].Document = document
            logDiagnostic("Updated managed policy document for %s", policy.Name)
        }
    }
    
    return nil
}

func decodePolicy(policyDocument string) (string, error) {
	logDiagnostic("Attempting to decode policy document of length %d", len(policyDocument))
	
	needsUrlDecoding := strings.Contains(policyDocument, "%")
	
	if needsUrlDecoding {
		logDiagnostic("Policy document appears to be URL-encoded, attempting to unescape")
	}
	
	docToUse := policyDocument
	if needsUrlDecoding {
		unescaped, err := url.QueryUnescape(policyDocument)
		if err != nil {
			logDiagnostic("Error unescaping policy document: %v", err)
			return "", fmt.Errorf("error unescaping policy document: %v", err)
		}
		docToUse = unescaped
		logDiagnostic("Successfully URL-unescaped policy document to length %d", len(docToUse))
	}

	var policy interface{}
	
	if err := json.Unmarshal([]byte(docToUse), &policy); err != nil {
		logDiagnostic("Error parsing JSON policy document: %v", err)
	
		if strings.HasPrefix(docToUse, "\"") && strings.HasSuffix(docToUse, "\"") {
			logDiagnostic("Policy document is wrapped in quotes, attempting to unwrap")
			unwrapped := docToUse[1:len(docToUse)-1]
			
	
			unwrapped = strings.ReplaceAll(unwrapped, "\\\"", "\"")
			unwrapped = strings.ReplaceAll(unwrapped, "\\\\", "\\")
			
			if err := json.Unmarshal([]byte(unwrapped), &policy); err != nil {
				logDiagnostic("Error parsing JSON after unwrapping: %v", err)
				return "", err
			}
			logDiagnostic("Successfully parsed JSON after unwrapping quotes")
		} else {
			return "", err
		}
	} else {
		logDiagnostic("Successfully parsed JSON policy document")
	}
	
	pretty, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		logDiagnostic("Error prettifying JSON: %v", err)
		return "", err
	}
	
	return string(pretty), nil
}


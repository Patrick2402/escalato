package aws

import (
	"fmt"
	"time"
	"github.com/fatih/color"
	"escalato/internal/models"
)

func DisplayUsers(users []models.User, showAccessKeys, showPolicies, showGroups, showDetails bool) {
	if len(users) == 0 {
		fmt.Println("No Users")
		return
	}

	// no flags? show only users
	if !showAccessKeys && !showPolicies && !showGroups && !showDetails {
		fmt.Println("Users:")
		for _, user := range users {
			fmt.Println("-", user.UserName)
		}
		return
	}

	// detailed infos
	for i, user := range users {
		color.Cyan("User %d: %s \n", i+1, user.UserName)
		
		if showDetails {
			fmt.Printf("ID: %s\n", user.UserId)
			fmt.Printf("ARN: %s\n", user.Arn)
			fmt.Printf("Path: %s\n", user.Path)
			fmt.Printf("Creation Time: %s\n", user.CreateDate.Format(time.RFC3339))
		}
		
		if showGroups {
			fmt.Printf("Groups: ")
			if len(user.Groups) > 0 {
				fmt.Println()
				for _, group := range user.Groups {
					fmt.Printf("  - %s\n", group)
				}
			} else {
				fmt.Println("None")
			}
		}
		
		if showPolicies {
			color.Red("Policies: ")
			if len(user.Policies) > 0 {
				for _, policy := range user.Policies {
					if policy.Type == "Managed" {
						fmt.Printf("  - %s ==> (Managed, %s)\n", policy.Name, policy.Arn)
					} else {
						fmt.Printf("  - %s ==> (Inline)\n", policy.Name)
					}
				}
			} else {
				fmt.Println("None")
			}
		}
		
		// show access keys
		if showAccessKeys {
			fmt.Printf("Access keys: ")
			if len(user.AccessKeys) > 0 {
				fmt.Println()
				for _, key := range user.AccessKeys {
					fmt.Printf("  - Access Key:  %s \n    Status: %s\n    Created: %s\n", 
						key.Id, 
						key.Status, 
						key.CreateDate.Format(time.RFC3339))
					
					if key.LastUsed != nil {
						fmt.Println("    Last Activity: ", key.LastUsed.Date.Format(time.RFC3339))
						if key.LastUsed.Region != "" {
							fmt.Println("    Region: ", key.LastUsed.Region)
						}
						if key.LastUsed.ServiceName != "" {
							fmt.Println("    Service: ", key.LastUsed.ServiceName)
						}
						fmt.Println()
					} else {
						fmt.Println("    Last Activity: Never")
					}
				}
			} else {
				fmt.Println("None")
			}
		}
		
		fmt.Println()
	}
}


func DisplayRoles(roles []models.Role, showPolicies, showTrusted bool, showLastActivity bool) {
	if len(roles) == 0 {
		fmt.Println("No Roles")
		return
	}

 // no flags? show only roles
	if !showPolicies && !showTrusted {
		fmt.Println("Role:")
		for _, role := range roles {
			fmt.Println("-", role.RoleName)
		}
		return
	}

	for i, role := range roles {
		color.Cyan("Role %d: %s\n", i+1, role.RoleName)
		// fmt.Printf("ID: %s\n", role.RoleId)
		fmt.Printf("ARN: %s\n", role.Arn)
		fmt.Printf("Path: %s\n", role.Path)
		fmt.Printf("Creation Time: %s\n", role.CreateDate.Format(time.RFC3339))
		
		if showPolicies {
			color.Red("Policy: ")
			if len(role.Policies) > 0 {
				// fmt.Println()
				for _, policy := range role.Policies {
					if policy.Type == "Managed" {
						fmt.Printf("  - %s ==> (Managed, %s)\n", policy.Name, policy.Arn)
					} else {
						fmt.Printf("  - %s ==> (Inline)\n", policy.Name)
					}
				}
			} else {
				fmt.Println("None")
			}
		}
		if showLastActivity {

			if role.LastUsed != nil {
				fmt.Printf("Last Activity: %s", role.LastUsed.Date.Format(time.RFC3339))
				fmt.Println()
			} else {
				fmt.Println("Last Activity: Never")
			}
		}

		if showTrusted && role.TrustPolicy != "" {
			fmt.Println("Trusted Policy:")
			fmt.Printf("```json\n%s\n```\n", role.TrustPolicy)
		}
		fmt.Println()
	}
}
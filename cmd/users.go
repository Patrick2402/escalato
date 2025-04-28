package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"escalato/internal/aws"
)

var (
	showAccessKeys bool
	showPolicies   bool
	showGroups     bool
	showDetails    bool
)

var usersCmd = &cobra.Command{
	Use:   "users",
	Short: "Shows IAM Users",
	Long:  `Show IAM users, Access keys, groups, policies.`,
	Run: func(cmd *cobra.Command, args []string) {
		profile, _ := cmd.Flags().GetString("profile")
		region, _ := cmd.Flags().GetString("region")

		client, err := aws.NewClient(context.Background(), profile, region)
		if err != nil {
			er(fmt.Sprintf("Error creating client AWS: %v", err))
		}

		users, err := aws.GetIAMUsers(context.Background(), client.IAMClient, 
			showAccessKeys, showPolicies, showGroups, showDetails)
		if err != nil {
			er(fmt.Sprintf("Error during fetchning users: %v", err))
		}

		aws.DisplayUsers(users, showAccessKeys, showPolicies, showGroups, showDetails)
	},
}

func init() {
	rootCmd.AddCommand(usersCmd)

	usersCmd.Flags().BoolVar(&showAccessKeys, "access-keys", false, "Show access keys")
	usersCmd.Flags().BoolVar(&showPolicies, "policies", false, "Show policies")
	usersCmd.Flags().BoolVar(&showGroups, "groups", false, "Show groups")
	usersCmd.Flags().BoolVar(&showDetails, "details", false, "Show details")
}
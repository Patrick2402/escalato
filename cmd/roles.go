package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"escalato/internal/aws"
)

var (
	showRolePolicies bool
	showRoleTrusted  bool
	showLastActivity bool
)

var rolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "Shows IAM Roles",
	Long:  `Show list of roles and policies.`,
	Run: func(cmd *cobra.Command, args []string) {
		profile, _ := cmd.Flags().GetString("profile")
		region, _ := cmd.Flags().GetString("region")

		client, err := aws.NewClient(context.Background(), profile, region)
		if err != nil {
			er(fmt.Sprintf("Could not create client AWS: %v", err))
		}

		roles, err := aws.GetIAMRoles(context.Background(), client.IAMClient, 
			showRolePolicies, showRoleTrusted, showLastActivity)
		if err != nil {
			er(fmt.Sprintf("Error during listing roles: %v", err))
		}

		aws.DisplayRoles(roles, showRolePolicies, showRoleTrusted, showLastActivity)
	},
}

func init() {
	rootCmd.AddCommand(rolesCmd)

	rolesCmd.Flags().BoolVar(&showRolePolicies, "policies", false, "Show policies")
	rolesCmd.Flags().BoolVar(&showRoleTrusted, "trusted", false, "Show trusted entities")
	rolesCmd.Flags().BoolVar(&showLastActivity, "last-activity", false, "Show last activity")
}
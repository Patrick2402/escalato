package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"escalato/internal/aws"
	"escalato/internal/rules"
	"escalato/internal/validator"
)

var (
	rulesFile      string
	outputJson     string
	enableDiagnostics bool
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validates IAM roles and users against security rules",
	Long:  `Validates IAM roles and users against security rules defined in a YAML file.`,
	Run: func(cmd *cobra.Command, args []string) {
		profile, _ := cmd.Flags().GetString("profile")
		region, _ := cmd.Flags().GetString("region")

		// Włącz diagnostykę jeśli wybrano
		if enableDiagnostics {
			aws.EnableDiagnostics = true
			validator.EnableDiagnostics = true
			fmt.Println("Diagnostic mode enabled. Detailed logs will be written to stderr.")
		}

		client, err := aws.NewClient(context.Background(), profile, region)
		if err != nil {
			er(fmt.Sprintf("Could not create AWS client: %v", err))
		}

		// Load rules from file
		ruleSet, err := rules.LoadRulesFromFile(rulesFile)
		if err != nil {
			er(fmt.Sprintf("Error loading rules: %v", err))
		}

		if enableDiagnostics {
			fmt.Fprintf(os.Stderr, "[DIAG] Loaded %d rules from %s\n", len(ruleSet.Rules), rulesFile)
		}

		// Get IAM data
		fmt.Println("Fetching IAM roles...")
		roles, err := aws.GetIAMRoles(context.Background(), client.IAMClient, true, true, true)
		if err != nil {
			er(fmt.Sprintf("Error fetching IAM roles: %v", err))
		}

		fmt.Println("Fetching IAM users...")
		users, err := aws.GetIAMUsers(context.Background(), client.IAMClient, true, true, true, true)
		if err != nil {
			er(fmt.Sprintf("Error fetching IAM users: %v", err))
		}

		fmt.Printf("Retrieved %d roles and %d users\n", len(roles), len(users))

		// Run validation
		fmt.Println("Running validation...")
		validationResults, err := validator.ValidateAll(ruleSet, roles, users)
		if err != nil {
			er(fmt.Sprintf("Error during validation: %v", err))
		}

		// Display results in console
		validator.DisplayResults(validationResults)

		// Export to JSON if requested
		if outputJson != "" {
			fmt.Printf("Exporting results to %s...\n", outputJson)
			err := exportToJson(validationResults, outputJson)
			if err != nil {
				er(fmt.Sprintf("Failed to export results to JSON: %v", err))
			}
			fmt.Printf("Results exported to %s\n", outputJson)
		}
	},
}

func exportToJson(results *validator.ValidationResults, outputPath string) error {
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, jsonData, 0644)
}

func init() {
	rootCmd.AddCommand(validateCmd)
	
	validateCmd.Flags().StringVar(&rulesFile, "rules", "escalato-rules.yml", "Path to the YAML file with validation rules")
	validateCmd.Flags().StringVar(&outputJson, "output-json", "", "Export results to JSON file")
	validateCmd.Flags().BoolVar(&enableDiagnostics, "diagnostics", false, "Enable diagnostic output for debugging")
}
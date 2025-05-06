package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"escalato/internal/aws"
	"escalato/internal/models"
	"escalato/internal/rules"
	"escalato/internal/validator"

	"github.com/spf13/cobra"
)

var (
	rulesFile          string
	outputJson         string
	enableDiagnostics  bool
	minConfidenceLevel string // Minimum confidence level to display
	minSeverityLevel   string // Minimum severity level to display
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validates IAM roles and users against security rules",
	Long:  `Validates IAM roles and users against security rules defined in a YAML file.`,
	Run: func(cmd *cobra.Command, args []string) {
		profile, _ := cmd.Flags().GetString("profile")
		region, _ := cmd.Flags().GetString("region")

		// Enable diagnostics
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

		fmt.Println("Fetching managed policy documents...")

		for i := range roles {
			if err := client.UpdateRolePoliciesWithDocuments(context.Background(), &roles[i]); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Error fetching managed policies for role %s: %v\n",
					roles[i].RoleName, err)
			}
		}

		for i := range users {
			if err := client.UpdateUserPoliciesWithDocuments(context.Background(), &users[i]); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Error fetching managed policies for user %s: %v\n",
					users[i].UserName, err)
			}
		}

		// Run validation
		fmt.Println("Running validation...")
		validationResults, err := validator.ValidateAll(ruleSet, roles, users)
		if err != nil {
			er(fmt.Sprintf("Error during validation: %v", err))
		}

		// Filter results by confidence and severity if specified
		if minConfidenceLevel != "" || minSeverityLevel != "" {
			filteredResults := filterResults(validationResults, minSeverityLevel, minConfidenceLevel)
			validationResults = filteredResults

			if minConfidenceLevel != "" && minSeverityLevel != "" {
				fmt.Printf("Filtered results to minimum severity: %s and minimum confidence: %s\n",
					minSeverityLevel, minConfidenceLevel)
			} else if minConfidenceLevel != "" {
				fmt.Printf("Filtered results to minimum confidence: %s\n", minConfidenceLevel)
			} else if minSeverityLevel != "" {
				fmt.Printf("Filtered results to minimum severity: %s\n", minSeverityLevel)
			}
		}

		// Display results in console
		validator.DisplayResults(validationResults)

		// Export to JSON
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

// Filter results by confidence and severity
func filterResults(results *validator.ValidationResults, minSeverity, minConfidence string) *validator.ValidationResults {
	if minSeverity == "" && minConfidence == "" {
		return results
	}

	var filteredViolations []models.Violation

	for _, violation := range results.Violations {
		includeViolation := true

		// Check severity filter
		if minSeverity != "" {
			severityPass := false
			switch minSeverity {
			case "CRITICAL":
				severityPass = violation.Severity == models.Critical
			case "HIGH":
				severityPass = violation.Severity == models.Critical ||
					violation.Severity == models.High
			case "MEDIUM":
				severityPass = violation.Severity == models.Critical ||
					violation.Severity == models.High ||
					violation.Severity == models.Medium
			case "LOW":
				severityPass = violation.Severity == models.Critical ||
					violation.Severity == models.High ||
					violation.Severity == models.Medium ||
					violation.Severity == models.Low
			case "INFO":
				severityPass = true // All severities pass
			default:
				severityPass = true // Invalid severity filter, include all
			}

			if !severityPass {
				includeViolation = false
			}
		}

		// Check confidence filter
		if minConfidence != "" && includeViolation {
			confidencePass := false
			switch minConfidence {
			case "HIGH":
				confidencePass = violation.Confidence == models.HighConfidence
			case "MEDIUM":
				confidencePass = violation.Confidence == models.HighConfidence ||
					violation.Confidence == models.MediumConfidence
			case "LOW":
				confidencePass = violation.Confidence == models.HighConfidence ||
					violation.Confidence == models.MediumConfidence ||
					violation.Confidence == models.LowConfidence
			case "INFO":
				confidencePass = true // All confidences pass
			default:
				confidencePass = true // Invalid confidence filter, include all
			}

			if !confidencePass {
				includeViolation = false
			}
		}

		if includeViolation {
			filteredViolations = append(filteredViolations, violation)
		}
	}

	// Create new results with filtered violations
	filteredResults := &validator.ValidationResults{
		Summary: validator.ValidationSummary{
			TotalRoles:      results.Summary.TotalRoles,
			TotalUsers:      results.Summary.TotalUsers,
			TotalViolations: len(filteredViolations),
		},
		Violations: filteredViolations,
	}

	// Recalculate summary counts
	for _, violation := range filteredViolations {
		switch violation.Severity {
		case models.Critical:
			filteredResults.Summary.CriticalViolations++
		case models.High:
			filteredResults.Summary.HighViolations++
		case models.Medium:
			filteredResults.Summary.MediumViolations++
		case models.Low:
			filteredResults.Summary.LowViolations++
		case models.Info:
			filteredResults.Summary.InfoViolations++
		}

		switch violation.Confidence {
		case models.HighConfidence:
			filteredResults.Summary.HighConfidenceViolations++
		case models.MediumConfidence:
			filteredResults.Summary.MediumConfidenceViolations++
		case models.LowConfidence:
			filteredResults.Summary.LowConfidenceViolations++
		case models.InfoConfidence:
			filteredResults.Summary.InfoConfidenceViolations++
		}
	}

	return filteredResults
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
	validateCmd.Flags().StringVar(&minConfidenceLevel, "min-confidence", "", "Minimum confidence level to display (HIGH, MEDIUM, LOW, INFO)")
	validateCmd.Flags().StringVar(&minSeverityLevel, "min-severity", "", "Minimum severity level to display (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
}

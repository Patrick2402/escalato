package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	
	"escalato/internal/aws"
	"escalato/internal/models"
	"escalato/internal/rules"
	"escalato/internal/validator"
)

var (
	rulesFile          string
	outputJson         string
	enableDiagnostics  bool
	minConfidenceLevel string
	minSeverityLevel   string
	skipAwsRoles       bool
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validates IAM roles and users against security rules",
	Long:  `Validates IAM roles and users against security rules defined in a YAML file.`,
	Run: func(cmd *cobra.Command, args []string) {
		profile, _ := cmd.Flags().GetString("profile")
		region, _ := cmd.Flags().GetString("region")

		// Enable diagnostics if requested
		if enableDiagnostics {
			fmt.Println("Diagnostic mode enabled. Detailed logs will be written to stderr.")
		}

		// Create AWS client
		client, err := aws.NewClient(context.Background(), profile, region)
		if err != nil {
			er(fmt.Sprintf("Could not create AWS client: %v", err))
		}

		// Load rules from file
		ruleSet, err := rules.LoadRulesFromFile(rulesFile)
		if err != nil {
			er(fmt.Sprintf("Error loading rules: %v", err))
		}

		fmt.Printf("Loaded %d rules from %s\n", len(ruleSet.Rules), rulesFile)

		// Fetch IAM data
		fmt.Println("Fetching IAM roles...")
		awsRoles, err := aws.GetIAMRoles(context.Background(), client.IAMClient, true, true, true)
		if err != nil {
			er(fmt.Sprintf("Error fetching IAM roles: %v", err))
		}

		fmt.Println("Fetching IAM users...")
		awsUsers, err := aws.GetIAMUsers(context.Background(), client.IAMClient, true, true, true, true)
		if err != nil {
			er(fmt.Sprintf("Error fetching IAM users: %v", err))
		}

		fmt.Printf("Retrieved %d roles and %d users\n", len(awsRoles), len(awsUsers))

		// Fetch policy documents
		fmt.Println("Fetching managed policy documents...")
		for i := range awsRoles {
			if err := client.UpdateRolePoliciesWithDocuments(context.Background(), &awsRoles[i]); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Error fetching managed policies for role %s: %v\n",
					awsRoles[i].RoleName, err)
			}
		}

		for i := range awsUsers {
			if err := client.UpdateUserPoliciesWithDocuments(context.Background(), &awsUsers[i]); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Error fetching managed policies for user %s: %v\n",
					awsUsers[i].UserName, err)
			}
		}

		// Create maps for quick lookups of excluded resources
		excludedRoles := make(map[string]bool)
		for _, roleName := range ruleSet.ExcludedRoles {
			excludedRoles[roleName] = true
		}

		excludedUsers := make(map[string]bool)
		for _, userName := range ruleSet.ExcludedUsers {
			excludedUsers[userName] = true
		}

		// Convert AWS resources to generic resources
		var resources []models.Resource
		skippedRoles := 0
		excludedRolesCount := 0

		for i := range awsRoles {
			// Skip AWS managed roles if the flag is set
			if skipAwsRoles && isAWSManagedRole(awsRoles[i].RoleName, awsRoles[i].Path) {
				if enableDiagnostics {
					fmt.Printf("Skipping AWS managed role: %s\n", awsRoles[i].RoleName)
				}
				skippedRoles++
				continue
			}
			
			// Skip roles in the exclusion list
			if excludedRoles[awsRoles[i].RoleName] {
				if enableDiagnostics {
					fmt.Printf("Excluding role from validation: %s\n", awsRoles[i].RoleName)
				}
				excludedRolesCount++
				continue
			}
			
			resources = append(resources, &awsRoles[i])
		}
		
		excludedUsersCount := 0
		for i := range awsUsers {
			// Skip users in the exclusion list
			if excludedUsers[awsUsers[i].UserName] {
				if enableDiagnostics {
					fmt.Printf("Excluding user from validation: %s\n", awsUsers[i].UserName)
				}
				excludedUsersCount++
				continue
			}
			
			resources = append(resources, &awsUsers[i])
		}

		if skippedRoles > 0 {
			fmt.Printf("Skipped %d AWS managed roles\n", skippedRoles)
		}
		if excludedRolesCount > 0 {
			fmt.Printf("Excluded %d roles based on exclusion list\n", excludedRolesCount)
		}
		if excludedUsersCount > 0 {
			fmt.Printf("Excluded %d users based on exclusion list\n", excludedUsersCount)
		}

		// Create validator registry and rule engine
		validatorRegistry := rules.NewValidatorRegistry(enableDiagnostics)
		
		// Register all validators
		registerValidators(validatorRegistry, enableDiagnostics)
		
		ruleEngine := rules.NewRuleEngine(validatorRegistry, enableDiagnostics)

		// Run validation
		fmt.Println("Running validation...")
		validationResults, err := ruleEngine.ValidateAll(ruleSet, resources)
		if err != nil {
			er(fmt.Sprintf("Error during validation: %v", err))
		}

		// Filter results by confidence and severity if specified
		filteredResults := filterResults(validationResults, minSeverityLevel, minConfidenceLevel)

		// Display filtering info if any filters were applied
		if minConfidenceLevel != "" || minSeverityLevel != "" {
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
		validator.DisplayResults(filteredResults)

		// Export to JSON if requested
		if outputJson != "" {
			fmt.Printf("Exporting results to %s...\n", outputJson)
			if err := validator.ExportToJSON(filteredResults, outputJson); err != nil {
				er(fmt.Sprintf("Failed to export results to JSON: %v", err))
			}
			fmt.Printf("Results exported to %s\n", outputJson)
		}
	},
}

// isAWSManagedRole checks if a role is an AWS managed role
func isAWSManagedRole(roleName, rolePath string) bool {
	// Check path containing aws-service-role
	if strings.Contains(rolePath, "/aws-service-role/") {
		return true
	}
	
	// Check for AWSServiceRole prefix (specifically for AWS service roles)
	if strings.HasPrefix(roleName, "AWSServiceRole") {
		return true
	}
	
	// Check for specific AWS prefixes (not ALL AWS prefixes)
	awsPrefixes := []string{
		"AWSServiceRoleFor",
		"AWS-QuickSetup",
		"AmazonSSM",
		"AmazonMQ",
	}
	
	for _, prefix := range awsPrefixes {
		if strings.HasPrefix(roleName, prefix) {
			return true
		}
	}
	
	// DO NOT skip SSO roles - they may have important permissions
	if strings.Contains(roleName, "AWSReservedSSO") {
		return false
	}
	
	// Other typical AWS roles
	awsRoles := []string{
		"OrganizationAccountAccessRole",
		"admin",
		"administrator",
		"ec2-instance-connect",
		"ecsTaskExecutionRole",
		"rds-monitoring-role",
	}
	
	for _, role := range awsRoles {
		if strings.EqualFold(roleName, role) {
			return true
		}
	}
	
	return false
}

// registerValidators registers all validators in the registry
// In the registerValidators function add:
func registerValidators(registry *rules.ValidatorRegistry, diagnostics bool) {
	// Logic validators
	registry.RegisterValidator(models.AndCondition, 
		validator.NewAndValidator(registry, diagnostics))
	registry.RegisterValidator(models.OrCondition, 
		validator.NewOrValidator(registry, diagnostics))
	registry.RegisterValidator(models.NotCondition, 
		validator.NewNotValidator(registry, diagnostics))
	
	// Resource validators
	registry.RegisterValidator(models.ResourcePropertyCondition, 
		validator.NewResourcePropertyValidator(diagnostics))
	registry.RegisterValidator(models.PatternMatchCondition, 
		validator.NewPatternMatchValidator(diagnostics))
	
	// Policy validators
	registry.RegisterValidator(models.PolicyDocumentCondition, 
		validator.NewPolicyDocumentValidator(diagnostics))
	
	// All policies validator
	registry.RegisterValidator(models.AllPoliciesCondition, 
		validator.NewAllPoliciesValidator(diagnostics))
	
	// Time validators
	registry.RegisterValidator(models.AgeCondition, 
		validator.NewAgeValidator(diagnostics))
		
	// Unused permissions validator
	registry.RegisterValidator(models.UnusedPermissionsCondition, 
		validator.NewUnusedPermissionsValidator(diagnostics))
}

// filterResults filters validation results by confidence and severity
func filterResults(results *models.ValidationResults, minSeverity, minConfidence string) *models.ValidationResults {
	if minSeverity == "" && minConfidence == "" {
		return results // No filtering needed
	}

	filteredResults := models.NewValidationResults()
	filteredResults.Summary.TotalResources = results.Summary.TotalResources
	filteredResults.Summary.TotalResourcesByType = results.Summary.TotalResourcesByType

	// Copy the resource counts
	for resourceType, count := range results.Summary.TotalResourcesByType {
		filteredResults.Summary.TotalResourcesByType[resourceType] = count
	}

	// Define the minimum severity level
	var minSeverityLevel models.Severity
	switch minSeverity {
	case "CRITICAL":
		minSeverityLevel = models.Critical
	case "HIGH":
		minSeverityLevel = models.High
	case "MEDIUM":
		minSeverityLevel = models.Medium
	case "LOW":
		minSeverityLevel = models.Low
	case "INFO":
		minSeverityLevel = models.Info
	default:
		minSeverityLevel = ""
	}

	// Define the minimum confidence level
	var minConfidenceLevel models.Confidence
	switch minConfidence {
	case "HIGH":
		minConfidenceLevel = models.HighConfidence
	case "MEDIUM":
		minConfidenceLevel = models.MediumConfidence
	case "LOW":
		minConfidenceLevel = models.LowConfidence
	case "INFO":
		minConfidenceLevel = models.InfoConfidence
	default:
		minConfidenceLevel = ""
	}

	// Filter violations
	for _, violation := range results.Violations {
		includeSeverity := minSeverityLevel == "" || isSeverityAtLeast(violation.Severity, minSeverityLevel)
		includeConfidence := minConfidenceLevel == "" || isConfidenceAtLeast(violation.Confidence, minConfidenceLevel)

		if includeSeverity && includeConfidence {
			filteredResults.AddViolation(violation)
		}
	}

	return filteredResults
}

// isSeverityAtLeast checks if a severity is at least a minimum level
func isSeverityAtLeast(severity, minLevel models.Severity) bool {
	severityOrder := map[models.Severity]int{
		models.Critical: 5,
		models.High:     4,
		models.Medium:   3,
		models.Low:      2,
		models.Info:     1,
	}

	return severityOrder[severity] >= severityOrder[minLevel]
}

// isConfidenceAtLeast checks if a confidence is at least a minimum level
func isConfidenceAtLeast(confidence, minLevel models.Confidence) bool {
	confidenceOrder := map[models.Confidence]int{
		models.HighConfidence:   4,
		models.MediumConfidence: 3,
		models.LowConfidence:    2,
		models.InfoConfidence:   1,
	}

	return confidenceOrder[confidence] >= confidenceOrder[minLevel]
}

func init() {
	rootCmd.AddCommand(validateCmd)

	validateCmd.Flags().StringVar(&rulesFile, "rules", "escalato-rules.yml", "Path to the YAML file with validation rules")
	validateCmd.Flags().StringVar(&outputJson, "output-json", "", "Export results to JSON file")
	validateCmd.Flags().BoolVar(&enableDiagnostics, "diagnostics", false, "Enable diagnostic output for debugging")
	validateCmd.Flags().StringVar(&minConfidenceLevel, "min-confidence", "", "Minimum confidence level to display (HIGH, MEDIUM, LOW, INFO)")
	validateCmd.Flags().StringVar(&minSeverityLevel, "min-severity", "", "Minimum severity level to display (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
	validateCmd.Flags().BoolVar(&skipAwsRoles, "skip-aws-roles", true, "Skip AWS managed roles during validation")
}
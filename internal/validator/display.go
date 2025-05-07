package validator

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"escalato/internal/models"
)

// DisplayResults formats and prints the validation results
func DisplayResults(results *models.ValidationResults) {
	fmt.Println("============================================")
	fmt.Println("          ESCALATO VALIDATION RESULTS       ")
	fmt.Println("============================================")
	fmt.Println()

	fmt.Printf("Total resources scanned: %d\n", results.Summary.TotalResources)
	
	// Show breakdown of resources by type
	for resType, count := range results.Summary.TotalResourcesByType {
		fmt.Printf("  %s: %d\n", resType, count)
	}
	
	fmt.Printf("\nTotal violations found: %d\n", results.Summary.TotalViolations)
	fmt.Println()

	// Setup colors for different severity levels
	criticalColor := color.New(color.FgRed, color.Bold)
	highColor := color.New(color.FgRed)
	mediumColor := color.New(color.FgYellow)
	lowColor := color.New(color.FgCyan)
	infoColor := color.New(color.FgBlue)

	// Print severity breakdown
	criticalColor.Printf("CRITICAL: %d violations\n", 
		results.Summary.ViolationsBySeverity[models.Critical])
	highColor.Printf("HIGH: %d violations\n", 
		results.Summary.ViolationsBySeverity[models.High])
	mediumColor.Printf("MEDIUM: %d violations\n", 
		results.Summary.ViolationsBySeverity[models.Medium])
	lowColor.Printf("LOW: %d violations\n", 
		results.Summary.ViolationsBySeverity[models.Low])
	infoColor.Printf("INFO: %d violations\n", 
		results.Summary.ViolationsBySeverity[models.Info])
	fmt.Println()
	
	// Print confidence level breakdown
	highConfColor := color.New(color.FgRed, color.Bold)
	medConfColor := color.New(color.FgYellow)
	lowConfColor := color.New(color.FgCyan)
	
	fmt.Println("Confidence Level Breakdown:")
	highConfColor.Printf("HIGH CONFIDENCE: %d violations\n", 
		results.Summary.ViolationsByConfidence[models.HighConfidence])
	medConfColor.Printf("MEDIUM CONFIDENCE: %d violations\n", 
		results.Summary.ViolationsByConfidence[models.MediumConfidence])
	lowConfColor.Printf("LOW CONFIDENCE: %d violations\n", 
		results.Summary.ViolationsByConfidence[models.LowConfidence])
	fmt.Println()

	// If no violations, show a success message
	if results.Summary.TotalViolations == 0 {
		color.Green("✅ No violations found. All resources comply with the defined rules.")
		return
	}

	// Display violations by severity
	displayViolationsByLevel(results.Violations, models.Critical, criticalColor)
	displayViolationsByLevel(results.Violations, models.High, highColor)
	displayViolationsByLevel(results.Violations, models.Medium, mediumColor)
	displayViolationsByLevel(results.Violations, models.Low, lowColor)
	displayViolationsByLevel(results.Violations, models.Info, infoColor)
}

// displayViolationsByLevel shows violations of a specific severity level
func displayViolationsByLevel(violations []models.Violation, level models.Severity, colorizer *color.Color) {
	levelViolations := filterViolationsByLevel(violations, level)
	if len(levelViolations) == 0 {
		return
	}

	colorizer.Printf("=== %s (%d) ===\n", level, len(levelViolations))
	
	for i, violation := range levelViolations {
		colorizer.Printf("%d. %s\n", i+1, violation.RuleName)
		fmt.Printf("   Resource: %s (%s)\n", violation.ResourceName, violation.ResourceType)
		fmt.Printf("   ARN: %s\n", violation.ResourceARN)
		
		// Display confidence with appropriate color
		displayConfidence(violation.Confidence)
		
		fmt.Printf("   Details: %s\n", violation.Details)
		fmt.Printf("   Detected: %s\n", 
			violation.Timestamp.Format(time.RFC3339))
		
		// Show additional context if available
		if len(violation.Context) > 0 {
			fmt.Println("   Context:")
			for k, v := range violation.Context {
				// Skip internal context variables
				if strings.HasPrefix(k, "_") {
					continue
				}
				
				// Skip long arrays and objects
				switch val := v.(type) {
				case []string:
					if len(val) > 3 {
						fmt.Printf("     %s: [%s, ... (%d more)]\n", 
							k, strings.Join(val[:3], ", "), len(val)-3)
						continue
					}
				}
				
				fmt.Printf("     %s: %v\n", k, v)
			}
		}
		
		fmt.Println()
	}
}

// displayConfidence shows the confidence level with appropriate color
func displayConfidence(confidence models.Confidence) {
	var confColor *color.Color
	
	switch confidence {
	case models.HighConfidence:
		confColor = color.New(color.FgRed, color.Bold)
	case models.MediumConfidence:
		confColor = color.New(color.FgYellow)
	case models.LowConfidence:
		confColor = color.New(color.FgCyan)
	case models.InfoConfidence:
		confColor = color.New(color.FgBlue)
	default:
		confColor = color.New(color.FgWhite)
	}
	
	confColor.Printf("   Confidence: %s\n", confidence)
}

// filterViolationsByLevel returns violations of a specific severity
func filterViolationsByLevel(violations []models.Violation, level models.Severity) []models.Violation {
	var filtered []models.Violation
	for _, v := range violations {
		if v.Severity == level {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// ExportToJSON exports validation results to a JSON file
func ExportToJSON(results *models.ValidationResults, outputPath string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling results to JSON: %w", err)
	}
	
	return os.WriteFile(outputPath, data, 0644)
}
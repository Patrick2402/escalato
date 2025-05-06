package validator

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"escalato/internal/models"
)


func DisplayResults(results *ValidationResults) {
	fmt.Println("============================================")
	fmt.Println("          ESCALATO VALIDATION RESULTS       ")
	fmt.Println("============================================")
	fmt.Println()

	fmt.Printf("Total resources scanned: %d (Roles: %d, Users: %d)\n", 
		results.Summary.TotalRoles + results.Summary.TotalUsers,
		results.Summary.TotalRoles,
		results.Summary.TotalUsers)
	
	fmt.Printf("Total violations found: %d\n", results.Summary.TotalViolations)
	fmt.Println()

	criticalColor := color.New(color.FgRed, color.Bold)
	highColor := color.New(color.FgRed)
	mediumColor := color.New(color.FgYellow)
	lowColor := color.New(color.FgCyan)
	infoColor := color.New(color.FgBlue)

	criticalColor.Printf("CRITICAL: %d violations\n", results.Summary.CriticalViolations)
	highColor.Printf("HIGH: %d violations\n", results.Summary.HighViolations)
	mediumColor.Printf("MEDIUM: %d violations\n", results.Summary.MediumViolations)
	lowColor.Printf("LOW: %d violations\n", results.Summary.LowViolations)
	infoColor.Printf("INFO: %d violations\n", results.Summary.InfoViolations)
	fmt.Println()
	
	// Display confidence level summary
	highConfColor := color.New(color.FgRed, color.Bold)
	medConfColor := color.New(color.FgYellow)
	lowConfColor := color.New(color.FgCyan)
	
	fmt.Println("Confidence Level Breakdown:")
	highConfColor.Printf("HIGH CONFIDENCE: %d violations\n", results.Summary.HighConfidenceViolations)
	medConfColor.Printf("MEDIUM CONFIDENCE: %d violations\n", results.Summary.MediumConfidenceViolations)
	lowConfColor.Printf("LOW CONFIDENCE: %d violations\n", results.Summary.LowConfidenceViolations)
	fmt.Println()

	if results.Summary.TotalViolations == 0 {
		color.Green("✅ No violations found. All resources comply with the defined rules.")
		return
	}

	displayViolationsByLevel(results.Violations, models.Critical, criticalColor)
	displayViolationsByLevel(results.Violations, models.High, highColor)
	displayViolationsByLevel(results.Violations, models.Medium, mediumColor)
	displayViolationsByLevel(results.Violations, models.Low, lowColor)
	displayViolationsByLevel(results.Violations, models.Info, infoColor)
}


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
		fmt.Println()
	}
}

// Helper function to display confidence with color
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

func filterViolationsByLevel(violations []models.Violation, level models.Severity) []models.Violation {
	var filtered []models.Violation
	for _, v := range violations {
		if v.Severity == level {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// Filter violations by confidence level
func filterViolationsByConfidence(violations []models.Violation, confidence models.Confidence) []models.Violation {
	var filtered []models.Violation
	for _, v := range violations {
		if v.Confidence == confidence {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func Indent(s string, indent string) string {
	return indent + strings.Replace(s, "\n", "\n"+indent, -1)
}
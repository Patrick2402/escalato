package validator

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	
	"escalato/internal/models"
)

type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

type Statement struct {
	Effect    string      `json:"Effect"`
	Action    interface{} `json:"Action"`
	Resource  interface{} `json:"Resource"`
	Principal interface{} `json:"Principal,omitempty"`
	Condition interface{} `json:"Condition,omitempty"`
}

// Define prefixes for read-only actions
var readOnlyPrefixes = []string{
	"Get", "List", "Describe", "View", "Read", "Check", "Retrieve", "Monitor",
}

// Check if an action is read-only based on its prefix
func isReadOnlyAction(action string) bool {
	parts := strings.Split(action, ":")
	if len(parts) != 2 {
		return false
	}
	
	actionName := parts[1]
	
	for _, prefix := range readOnlyPrefixes {
		if strings.HasPrefix(actionName, prefix) {
			return true
		}
	}
	return false
}

// Helper function to get a clean policy display name
func getDisplayPolicyName(policyName string) string {
    // If it's an ARN, extract just the name part
    if strings.HasPrefix(policyName, "arn:aws:iam::") {
        parts := strings.Split(policyName, "/")
        if len(parts) > 1 {
            return parts[len(parts)-1]
        }
    }
    return policyName
}

// Helper function to check for wildcard in resources
func checkForWildcardResource(resources []string) bool {
	for _, resource := range resources {
		if resource == "*" || strings.Contains(resource, "*") {
			return true
		}
	}
	return false
}

func AnalyzeInlinePolicyDocument(policyName, policyDocument string, serviceToCheck, actionToCheck string) (bool, string, models.Confidence) {
	if EnableDiagnostics {
		fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Analyzing policy document: %s\n", policyName)
	}
	
	var doc PolicyDocument
	err := json.Unmarshal([]byte(policyDocument), &doc)
	if err != nil {
		if EnableDiagnostics {
			fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Failed to parse policy document %s: %v\n", policyName, err)
		}
		return false, fmt.Sprintf("Failed to parse policy document: %v", err), models.LowConfidence
	}

	// Pass the policy name to analyzeStatements
	return analyzeStatements(doc.Statement, serviceToCheck, actionToCheck, policyName)
}

func analyzeStatements(statements []Statement, serviceToCheck, actionToCheck string, policyName string) (bool, string, models.Confidence) {
	if EnableDiagnostics {
		fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Analyzing %d statements for service:%s action:%s in policy: %s\n", 
			len(statements), serviceToCheck, actionToCheck, policyName)
	}

	// Use a clean display name for the policy
	displayPolicyName := getDisplayPolicyName(policyName)

	// Checking for example. "s3:*"
	exactMatchToFind := serviceToCheck + ":" + actionToCheck
	
	for i, stmt := range statements {
		if strings.ToLower(stmt.Effect) != "allow" { // focus on allow statements
			if EnableDiagnostics {
				fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Skipping statement %d with effect: %s\n", i, stmt.Effect)
			}
			continue
		}

		var actions []string
		switch a := stmt.Action.(type) {
		case string:
			actions = []string{a}
		case []interface{}:
			for _, action := range a {
				if actionStr, ok := action.(string); ok {
					actions = append(actions, actionStr)
				}
			}
		case []string:
			actions = a
		default:
			if EnableDiagnostics {
				fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Unknown action type: %T\n", stmt.Action)
			}
		}
		
		if EnableDiagnostics {
			fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Statement %d has %d actions\n", i, len(actions))
		}

		var resources []string
		switch r := stmt.Resource.(type) {
		case string:
			resources = []string{r}
		case []interface{}:
			for _, resource := range r {
				if resourceStr, ok := resource.(string); ok {
					resources = append(resources, resourceStr)
				}
			}
		case []string:
			resources = r
		default:
			if EnableDiagnostics {
				fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Unknown resource type: %T\n", stmt.Resource)
			}
		}
		
		if EnableDiagnostics {
			fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Statement %d has %d resources\n", i, len(resources))
		}

		// Check for exact wildcard match first
		exactWildcardMatch := false
		for _, action := range actions {
			if action == exactMatchToFind {
				exactWildcardMatch = true
				if EnableDiagnostics {
					fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Found exact wildcard match for %s\n", exactMatchToFind)
				}
				break
			}
		}
		
		// If we have exact wildcard match
		if exactWildcardMatch {
			hasWildcardResource := checkForWildcardResource(resources)
			
			details := fmt.Sprintf("Policy '%s' contains exact wildcard match for %s", 
				displayPolicyName, exactMatchToFind)
			if hasWildcardResource {
				details += " on resources with wildcard"
			}
			
			if EnableDiagnostics {
				fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Exact wildcard violation found: %s\n", details)
			}
			
			// Determine confidence level
			confidence := models.MediumConfidence
			if hasWildcardResource {
				confidence = models.HighConfidence // Highest confidence for exact match with wildcards
			}
			
			return true, details, confidence
		}
		
		// If no exact wildcard match, check for accumulative permissions
		if actionToCheck == "*" {
			serviceMatches := 0
			nonReadOnlyCount := 0
			var nonReadOnlyActions []string
			
			for _, action := range actions {
				if strings.HasPrefix(action, serviceToCheck + ":") {
					serviceMatches++
					if EnableDiagnostics {
						fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Found service action: %s\n", action)
					}
					
					// Check if this is a non-read-only action
					if !isReadOnlyAction(action) {
						nonReadOnlyCount++
						nonReadOnlyActions = append(nonReadOnlyActions, action)
						if EnableDiagnostics {
							fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Found non-read-only action: %s\n", action)
						}
					}
				}
			}
			
			// Only consider it a match if there are significant non-read-only actions
			if serviceMatches > 10 && nonReadOnlyCount >= 3 {
				hasWildcardResource := checkForWildcardResource(resources)
				
				// List up to 3 non-read-only actions in the details
				nonReadOnlyExamples := ""
				if len(nonReadOnlyActions) > 0 {
					maxToShow := 3
					if len(nonReadOnlyActions) < maxToShow {
						maxToShow = len(nonReadOnlyActions)
					}
					nonReadOnlyExamples = strings.Join(nonReadOnlyActions[:maxToShow], ", ")
					if len(nonReadOnlyActions) > maxToShow {
						nonReadOnlyExamples += ", ..."
					}
				}
				
				details := fmt.Sprintf("Policy '%s' contains %d non-read-only actions for %s (e.g., %s)", 
					displayPolicyName, nonReadOnlyCount, serviceToCheck, nonReadOnlyExamples)
				
				if hasWildcardResource {
					details += " on resources with wildcard"
				}
				
				if EnableDiagnostics {
					fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Accumulated permissions violation found: %s\n", details)
				}
				
				// Determine confidence level
				confidence := models.LowConfidence
				if nonReadOnlyCount > 5 {
					confidence = models.MediumConfidence
				}
				if hasWildcardResource && nonReadOnlyCount > 8 {
					confidence = models.HighConfidence
				}
				
				return true, details, confidence
			} else if serviceMatches > 0 {
				if EnableDiagnostics {
					fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Found %d actions for service %s (%d non-read-only), NOT enough to consider as wildcard\n", 
						serviceMatches, serviceToCheck, nonReadOnlyCount)
				}
			}
		}
	}

	if EnableDiagnostics {
		fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] No match found for %s:%s or insufficient non-read-only actions\n", 
			serviceToCheck, actionToCheck)
	}
	
	return false, "", models.LowConfidence
}
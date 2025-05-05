package validator

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
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

func AnalyzeInlinePolicyDocument(policyName, policyDocument string, serviceToCheck, actionToCheck string) (bool, string) {
	if EnableDiagnostics {
		fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Analyzing policy document: %s\n", policyName)
	}
	
	var doc PolicyDocument
	err := json.Unmarshal([]byte(policyDocument), &doc)
	if err != nil {
		if EnableDiagnostics {
			fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Failed to parse policy document %s: %v\n", policyName, err)
		}
		return false, fmt.Sprintf("Failed to parse policy document: %v", err)
	}

	return analyzeStatements(doc.Statement, serviceToCheck, actionToCheck)
}

func analyzeStatements(statements []Statement, serviceToCheck, actionToCheck string) (bool, string) {
	if EnableDiagnostics {
		fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Analyzing %d statements for service:%s action:%s\n", 
			len(statements), serviceToCheck, actionToCheck)
	}

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

		exactMatch := false
		
		for _, action := range actions {
			if action == exactMatchToFind {
				exactMatch = true
				if EnableDiagnostics {
					fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Found exact match for %s\n", exactMatchToFind)
				}
				break
			}
		}
		
		// check if actionToCheck is a wildcard "*"
		if !exactMatch && actionToCheck == "*" {
			serviceMatches := 0
			for _, action := range actions {
				if strings.HasPrefix(action, serviceToCheck + ":") {
					serviceMatches++
					if EnableDiagnostics {
						fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Found service action: %s\n", action)
					}
				}
			}
			
			// TO IMPROVE: IF serviceMatches > 10, consider as wildcard
			// remark from artur if number is called it like 10 and the,,. != starting from LIST/GET/ (read only) do not consider 
			if serviceMatches > 10 {
				exactMatch = true
				// dodaj tutaj logike zeby sprawdzacz tylko dla PUT/DELETE (nie read only things)  @patryk
				if EnableDiagnostics {
					fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Found %d actions for service %s, considering as equivalent to wildcard\n", 
						serviceMatches, serviceToCheck)
				}
			}
		}
		
		if exactMatch {
			hasWildcardResource := false
			for _, resource := range resources {
				if resource == "*" || strings.Contains(resource, "*") {
					hasWildcardResource = true
					if EnableDiagnostics {
						fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Found wildcard in resource: %s\n", resource)
					}
					break
				}
			}
			
			details := fmt.Sprintf("Policy contains exact match for %s", exactMatchToFind)
			if hasWildcardResource {
				details += " on resources with wildcard"
			}
			
			if EnableDiagnostics {
				fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Violation found: %s\n", details)
			}
			
			return true, details
		}
	}

	if EnableDiagnostics {
		fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] No exact match found for %s:%s\n", 
			serviceToCheck, actionToCheck)
	}
	
	return false, ""
}
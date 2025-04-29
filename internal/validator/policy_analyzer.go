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

	hasViolation, details := analyzeStatements(doc.Statement, serviceToCheck, actionToCheck)
	
	if EnableDiagnostics {
		if hasViolation {
			fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Found violation in policy %s: %s\n", policyName, details)
		} else {
			fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] No violation found in policy %s for service:%s action:%s\n", 
				policyName, serviceToCheck, actionToCheck)
		}
	}
	
	return hasViolation, details
}


// func analyzeStatements(statements []Statement, serviceToCheck, actionToCheck string) (bool, string) {
// 	// Jeśli sprawdzamy wildcard, dopasujemy *
// 	wildcardCheck := actionToCheck == "*"
	
// 	if EnableDiagnostics {
// 		fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Analyzing %d statements for service:%s action:%s\n", 
// 			len(statements), serviceToCheck, actionToCheck)
// 	}


// 	if serviceToCheck == "s3" && wildcardCheck {
// 		return analyzeS3FullAccessPolicy(statements)
// 	}

// 	for i, stmt := range statements {
// 		if strings.ToLower(stmt.Effect) != "allow" {
// 			if EnableDiagnostics {
// 				fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Skipping statement %d with effect: %s\n", i, stmt.Effect)
// 			}
// 			continue
// 		}

// 		var actions []string
// 		switch a := stmt.Action.(type) {
// 		case string:
// 			actions = []string{a}
// 		case []interface{}:
// 			for _, action := range a {
// 				if actionStr, ok := action.(string); ok {
// 					actions = append(actions, actionStr)
// 				}
// 			}
// 		case []string:
// 			actions = a
// 		default:
// 			if EnableDiagnostics {
// 				fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Unknown action type: %T\n", stmt.Action)
// 			}
// 		}
		
// 		if EnableDiagnostics {
// 			fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Statement %d has %d actions\n", i, len(actions))
// 		}

// 		var resources []string
// 		switch r := stmt.Resource.(type) {
// 		case string:
// 			resources = []string{r}
// 		case []interface{}:
// 			for _, resource := range r {
// 				if resourceStr, ok := resource.(string); ok {
// 					resources = append(resources, resourceStr)
// 				}
// 			}
// 		case []string:
// 			resources = r
// 		default:
// 			if EnableDiagnostics {
// 				fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Unknown resource type: %T\n", stmt.Resource)
// 			}
// 		}
		
// 		if EnableDiagnostics {
// 			fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Statement %d has %d resources\n", i, len(resources))
// 		}

// 		hasMatchingAction := false
// 		hasWildcardAction := false
// 		serviceMatch := false

// 		for _, action := range actions {
// 			parts := strings.Split(action, ":")
// 			if len(parts) >= 2 {
// 				service := parts[0]
// 				actionPart := parts[1]
				
// 				if EnableDiagnostics {
// 					fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Checking action %s:%s against %s:%s\n", 
// 						service, actionPart, serviceToCheck, actionToCheck)
// 				}

// 				if service == serviceToCheck {
// 					serviceMatch = true
// 					if actionPart == "*" {
// 						hasWildcardAction = true
// 						if EnableDiagnostics {
// 							fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Found wildcard action for service %s\n", service)
// 						}
// 					}
// 					if wildcardCheck || actionPart == actionToCheck || actionPart == "*" {
// 						hasMatchingAction = true
// 						if EnableDiagnostics {
// 							fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Found matching action %s:%s\n", service, actionPart)
// 						}
// 					}
// 				}
// 			}
// 		}

// 		// Sprawdź czy mamy wildcard w resource
// 		hasWildcardResource := false
// 		for _, resource := range resources {
// 			if strings.Contains(resource, "*") {
// 				hasWildcardResource = true
// 				if EnableDiagnostics {
// 					fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Found wildcard in resource: %s\n", resource)
// 				}
// 				break
// 			}
// 		}

// 		if serviceMatch && hasMatchingAction {
// 			var action string
// 			if hasWildcardAction {
// 				action = "*"
// 			} else {
// 				action = actionToCheck
// 			}
// 			details := fmt.Sprintf("Policy allows %s:%s", serviceToCheck, action)
			
// 			if hasWildcardResource {
// 				details += " on resources with wildcard"
// 			}
			
// 			if EnableDiagnostics {
// 				fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Violation found: %s\n", details)
// 			}
			
// 			return true, details
// 		}
// 	}

// 	if EnableDiagnostics {
// 		fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] No violations found in all statements\n")
// 	}
	
// 	return false, ""
// }

// analyzeStatements analizuje wszystkie instrukcje w polityce
func analyzeStatements(statements []Statement, serviceToCheck, actionToCheck string) (bool, string) {
	if EnableDiagnostics {
		fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Analyzing %d statements for service:%s action:%s\n", 
			len(statements), serviceToCheck, actionToCheck)
	}

	// Sprawdzanie dokładnego dopasowania serwisu:akcji, np. "s3:*"
	exactMatchToFind := serviceToCheck + ":" + actionToCheck
	
	for i, stmt := range statements {
		// Pomijamy deny statements - interesują nas tylko allow
		if strings.ToLower(stmt.Effect) != "allow" {
			if EnableDiagnostics {
				fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Skipping statement %d with effect: %s\n", i, stmt.Effect)
			}
			continue
		}

		// Analizuj actions
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

		// Analizuj resources
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

		// Sprawdź dokładne dopasowanie
		exactMatch := false
		
		// Sprawdź, czy actions zawiera dokładnie poszukiwaną akcję (np. "s3:*")
		for _, action := range actions {
			if action == exactMatchToFind {
				exactMatch = true
				if EnableDiagnostics {
					fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Found exact match for %s\n", exactMatchToFind)
				}
				break
			}
		}
		
		// Jeśli nie znaleziono dokładnego dopasowania, a sprawdzamy wildcard, 
		// sprawdź czy są oddzielne uprawnienia, które razem dają efekt wildcard
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
			
			// Jeśli jest bardzo dużo akcji dla tego serwisu, to prawdopodobnie jest to równoważne wildcard
			if serviceMatches > 10 {
				exactMatch = true
				if EnableDiagnostics {
					fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Found %d actions for service %s, considering as equivalent to wildcard\n", 
						serviceMatches, serviceToCheck)
				}
			}
		}
		
		// Jeśli znaleziono dopasowanie, sprawdź czy dotyczy wszystkich zasobów
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

func analyzeS3FullAccessPolicy(statements []Statement) (bool, string) {
	criticalS3Actions := map[string]bool{
		"s3:*":                          true,
		"s3:DeleteBucket":               true,
		"s3:DeleteBucketPolicy":         true,
		"s3:PutBucketPolicy":            true,
		"s3:PutBucketAcl":               true,
		"s3:PutLifecycleConfiguration":  true,
	}
	
	commonLimitedS3Actions := map[string]bool{
		"s3:GetObject":                  true,
		"s3:PutObject":                  true,
		"s3:ListBucket":                 true,
		"s3:AbortMultipartUpload":       true,
		"s3:GetBucketLocation":          true,
		"s3:ListBucketMultipartUploads": true,
		"s3:PutObjectAcl":               true,
	}
	
	hasFullAccess := false
	hasCriticalAccess := false
	isLimitedAccessPattern := true
	
	totalS3Actions := 0
	criticalActionsCount := 0
	nonLimitedActionsCount := 0
	

	for _, stmt := range statements {
		if strings.ToLower(stmt.Effect) != "allow" {
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
		}
		
		for _, action := range actions {
			if strings.HasPrefix(action, "s3:") {
				totalS3Actions++
				
				if criticalS3Actions[action] {
					criticalActionsCount++
					hasCriticalAccess = true
					
					if action == "s3:*" {
						hasFullAccess = true
					}
				}
				

				if !commonLimitedS3Actions[action] {
					nonLimitedActionsCount++
					
					if EnableDiagnostics {
						fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Found non-limited S3 action: %s\n", action)
					}
				}
			}
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
		}
		
		allBucketsAccess := false
		for _, resource := range resources {
			if resource == "*" || resource == "arn:aws:s3:::*" || resource == "arn:aws:s3:::*/*" {
				allBucketsAccess = true
				break
			}
		}
		
		if hasCriticalAccess && allBucketsAccess {
			hasFullAccess = true
		}
	}
	
	if EnableDiagnostics {
		fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] S3 policy analysis: totalActions=%d, criticalActions=%d, nonLimitedActions=%d\n", 
			totalS3Actions, criticalActionsCount, nonLimitedActionsCount)
		fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] S3 policy findings: hasFullAccess=%v, hasCriticalAccess=%v\n", 
			hasFullAccess, hasCriticalAccess)
	}
	

	if hasFullAccess || nonLimitedActionsCount > 3 {
		isLimitedAccessPattern = false
	}
	
	if isLimitedAccessPattern {
		if EnableDiagnostics {
			fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Limited S3 access pattern detected, not reporting violation\n")
		}
		return false, ""
	}
	
	details := "Policy allows full or extensive S3 access"
	if hasFullAccess {
		details = "Policy allows full S3 access (s3:*)"
	} else if hasCriticalAccess {
		details = "Policy allows critical S3 administrative actions"
	} else if totalS3Actions > 10 {
		details = fmt.Sprintf("Policy allows extensive S3 access (%d actions)", totalS3Actions)
	}
	
	if EnableDiagnostics {
		fmt.Fprintf(os.Stderr, "[DIAG-ANALYZER] Reporting S3 policy violation: %s\n", details)
	}
	
	return true, details
}

func CheckPolicyForServiceAccess(policyDocument, serviceName, actionName string) (bool, string) {
	var doc PolicyDocument
	err := json.Unmarshal([]byte(policyDocument), &doc)
	if err != nil {
		return false, fmt.Sprintf("Failed to parse policy document: %v", err)
	}

	return analyzeStatements(doc.Statement, serviceName, actionName)
}
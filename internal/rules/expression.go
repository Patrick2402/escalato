package rules

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"escalato/internal/models"
)

// ExpressionEvaluator evaluates expressions in rule conditions
type ExpressionEvaluator struct {
	// Function registry for expression evaluation
	functions map[string]ExpressionFunc
}

// ExpressionFunc is a function that can be called from an expression
type ExpressionFunc func(args ...interface{}) (interface{}, error)

// EvaluationContext holds the resource and collected data during rule evaluation
type EvaluationContext struct {
	Resource models.Resource
	Data     map[string]interface{}
}

// NewEvaluationContext creates a new evaluation context for a resource
func NewEvaluationContext(resource models.Resource) *EvaluationContext {
	return &EvaluationContext{
		Resource: resource,
		Data:     make(map[string]interface{}),
	}
}

// NewExpressionEvaluator creates a new expression evaluator with built-in functions
func NewExpressionEvaluator() *ExpressionEvaluator {
	e := &ExpressionEvaluator{
		functions: make(map[string]ExpressionFunc),
	}
	
	// Register built-in functions
	e.RegisterFunction("matches", func(args ...interface{}) (interface{}, error) {
		if len(args) != 2 {
			return nil, errors.New("matches requires 2 arguments")
		}
		
		str, ok := args[0].(string)
		if !ok {
			return nil, errors.New("first argument must be a string")
		}
		
		pattern, ok := args[1].(string)
		if !ok {
			return nil, errors.New("second argument must be a string")
		}
		
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %w", err)
		}
		
		return re.MatchString(str), nil
	})
	
	e.RegisterFunction("contains", func(args ...interface{}) (interface{}, error) {
		if len(args) != 2 {
			return nil, errors.New("contains requires 2 arguments")
		}
		
		str, ok := args[0].(string)
		if !ok {
			return nil, errors.New("first argument must be a string")
		}
		
		substr, ok := args[1].(string)
		if !ok {
			return nil, errors.New("second argument must be a string")
		}
		
		return strings.Contains(str, substr), nil
	})
	
	e.RegisterFunction("hasWildcard", func(args ...interface{}) (interface{}, error) {
		if len(args) != 1 {
			return nil, errors.New("hasWildcard requires 1 argument")
		}
		
		str, ok := args[0].(string)
		if !ok {
			return nil, errors.New("argument must be a string")
		}
		
		return strings.Contains(str, "*"), nil
	})

	return e
}

// RegisterFunction registers a function that can be called from expressions
func (e *ExpressionEvaluator) RegisterFunction(name string, fn ExpressionFunc) {
	e.functions[name] = fn
}

// Evaluate evaluates an expression using the provided data
func (e *ExpressionEvaluator) Evaluate(expression string, data map[string]interface{}) (interface{}, error) {
	// Simple expression evaluation for demonstration 
	// This is a basic implementation that handles:
	// - Boolean operators: && (AND), || (OR), ! (NOT)
	// - Comparison operators: ==, !=, >, <, >=, <=
	// - Variable references using the data map
	// - Function calls registered in the evaluator
	
	// First, check for simple boolean expressions
	switch strings.TrimSpace(expression) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	
	// Check for logical AND (&&)
	if parts := strings.Split(expression, "&&"); len(parts) > 1 {
		for _, part := range parts {
			result, err := e.Evaluate(strings.TrimSpace(part), data)
			if err != nil {
				return nil, fmt.Errorf("error evaluating AND expression '%s': %w", part, err)
			}
			
			boolResult, ok := result.(bool)
			if !ok {
				return nil, fmt.Errorf("expression '%s' did not evaluate to a boolean", part)
			}
			
			// Short-circuit evaluation
			if !boolResult {
				return false, nil
			}
		}
		return true, nil
	}
	
	// Check for logical OR (||)
	if parts := strings.Split(expression, "||"); len(parts) > 1 {
		for _, part := range parts {
			result, err := e.Evaluate(strings.TrimSpace(part), data)
			if err != nil {
				return nil, fmt.Errorf("error evaluating OR expression '%s': %w", part, err)
			}
			
			boolResult, ok := result.(bool)
			if !ok {
				return nil, fmt.Errorf("expression '%s' did not evaluate to a boolean", part)
			}
			
			// Short-circuit evaluation
			if boolResult {
				return true, nil
			}
		}
		return false, nil
	}
	
	// Check for logical NOT (!)
	if strings.HasPrefix(expression, "!") {
		subexpr := strings.TrimSpace(expression[1:])
		result, err := e.Evaluate(subexpr, data)
		if err != nil {
			return nil, fmt.Errorf("error evaluating NOT expression '%s': %w", subexpr, err)
		}
		
		boolResult, ok := result.(bool)
		if !ok {
			return nil, fmt.Errorf("expression '%s' did not evaluate to a boolean", subexpr)
		}
		
		return !boolResult, nil
	}
	
	// Check for comparison operators
	for _, op := range []string{"==", "!=", ">=", "<=", ">", "<"} {
		if parts := strings.Split(expression, op); len(parts) == 2 {
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])
			
			leftValue, err := e.evaluateValue(left, data)
			if err != nil {
				return nil, fmt.Errorf("error evaluating left side of '%s': %w", left, err)
			}
			
			rightValue, err := e.evaluateValue(right, data)
			if err != nil {
				return nil, fmt.Errorf("error evaluating right side of '%s': %w", right, err)
			}
			
			switch op {
			case "==":
				return reflect.DeepEqual(leftValue, rightValue), nil
			case "!=":
				return !reflect.DeepEqual(leftValue, rightValue), nil
			case ">":
				return e.compareValues(leftValue, rightValue, func(a, b float64) bool { return a > b })
			case "<":
				return e.compareValues(leftValue, rightValue, func(a, b float64) bool { return a < b })
			case ">=":
				return e.compareValues(leftValue, rightValue, func(a, b float64) bool { return a >= b })
			case "<=":
				return e.compareValues(leftValue, rightValue, func(a, b float64) bool { return a <= b })
			}
		}
	}
	
	// Handle function calls or variable references
	return e.evaluateValue(expression, data)
}

// evaluateValue evaluates a value which could be a variable, function call, or literal
func (e *ExpressionEvaluator) evaluateValue(expr string, data map[string]interface{}) (interface{}, error) {
	expr = strings.TrimSpace(expr)
	
	// Check for function calls (name(...args...))
	if match := regexp.MustCompile(`^(\w+)\((.*)\)$`).FindStringSubmatch(expr); len(match) == 3 {
		funcName := match[1]
		argsStr := match[2]
		
		fn, ok := e.functions[funcName]
		if !ok {
			return nil, fmt.Errorf("unknown function: %s", funcName)
		}
		
		// Parse arguments
		var args []interface{}
		if argsStr != "" {
			// Simple argument splitting (doesn't handle nested functions correctly)
			for _, arg := range strings.Split(argsStr, ",") {
				argValue, err := e.evaluateValue(strings.TrimSpace(arg), data)
				if err != nil {
					return nil, fmt.Errorf("error evaluating argument '%s': %w", arg, err)
				}
				args = append(args, argValue)
			}
		}
		
		// Call the function
		return fn(args...)
	}
	
	// Check for string literals
	if strings.HasPrefix(expr, "\"") && strings.HasSuffix(expr, "\"") {
		return expr[1 : len(expr)-1], nil
	}
	
	// Check for number literals
	if num, err := strconv.ParseFloat(expr, 64); err == nil {
		return num, nil
	}
	
	// Check for boolean literals
	if expr == "true" {
		return true, nil
	}
	if expr == "false" {
		return false, nil
	}
	
	// Try to get from data
	if value, ok := data[expr]; ok {
		return value, nil
	}
	
	// If we get here, we don't know what this is
	return nil, fmt.Errorf("unknown expression: %s", expr)
}

// compareValues compares two values using a comparison function
func (e *ExpressionEvaluator) compareValues(a, b interface{}, cmp func(a, b float64) bool) (interface{}, error) {
	// Convert values to comparable types
	var aFloat, bFloat float64
	var err error
	
	aFloat, err = e.toFloat(a)
	if err != nil {
		return nil, fmt.Errorf("left value cannot be compared: %w", err)
	}
	
	bFloat, err = e.toFloat(b)
	if err != nil {
		return nil, fmt.Errorf("right value cannot be compared: %w", err)
	}
	
	return cmp(aFloat, bFloat), nil
}

// toFloat converts a value to a float64
func (e *ExpressionEvaluator) toFloat(v interface{}) (float64, error) {
	switch val := v.(type) {
	case int:
		return float64(val), nil
	case int64:
		return float64(val), nil
	case float64:
		return val, nil
	case string:
		return strconv.ParseFloat(val, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", v)
	}
}
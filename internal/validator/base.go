package validator

import (
	"fmt"
	"log"
	
	"escalato/internal/models"
	"escalato/internal/rules"
)


type ConditionValidator interface {
	Validate(condition models.Condition, ctx *rules.EvaluationContext) (bool, error)
}

type BaseValidator struct {
	diagnostics bool
}


func NewBaseValidator(diagnostics bool) *BaseValidator {
	return &BaseValidator{
		diagnostics: diagnostics,
	}
}


func (v *BaseValidator) EnableDiagnostics(enable bool) {
	v.diagnostics = enable
}

func (v *BaseValidator) logDebug(format string, args ...interface{}) {
	if v.diagnostics {
		log.Printf("[VALIDATOR] "+format, args...)
	}
}

type AndValidator struct {
	*BaseValidator
	registry *rules.ValidatorRegistry
}

func NewAndValidator(registry *rules.ValidatorRegistry, diagnostics bool) ConditionValidator {
	return &AndValidator{
		BaseValidator: NewBaseValidator(diagnostics),
		registry:      registry,
	}
}

func (v *AndValidator) Validate(condition models.Condition, ctx *rules.EvaluationContext) (bool, error) {
	if len(condition.Conditions) == 0 {
		return true, nil
	}
	
	for _, subCondition := range condition.Conditions {
		validator, err := v.registry.GetValidator(subCondition.Type)
		if err != nil {
			return false, fmt.Errorf("error getting validator for sub-condition: %w", err)
		}
		
		matched, err := validator.Validate(subCondition, ctx)
		if err != nil {
			return false, fmt.Errorf("error validating sub-condition: %w", err)
		}
		
		if !matched {
			v.logDebug("AND condition failed on sub-condition type %s", subCondition.Type)
			return false, nil
		}
	}
	
	v.logDebug("AND condition passed with %d sub-conditions", len(condition.Conditions))
	return true, nil
}


type OrValidator struct {
	*BaseValidator
	registry *rules.ValidatorRegistry
}


func NewOrValidator(registry *rules.ValidatorRegistry, diagnostics bool) ConditionValidator {
	return &OrValidator{
		BaseValidator: NewBaseValidator(diagnostics),
		registry:      registry,
	}
}

func (v *OrValidator) Validate(condition models.Condition, ctx *rules.EvaluationContext) (bool, error) {

	if len(condition.Conditions) == 0 {
		return false, nil
	}
	
	for _, subCondition := range condition.Conditions {
		validator, err := v.registry.GetValidator(subCondition.Type)
		if err != nil {
			return false, fmt.Errorf("error getting validator for sub-condition: %w", err)
		}
		
		matched, err := validator.Validate(subCondition, ctx)
		if err != nil {
			return false, fmt.Errorf("error validating sub-condition: %w", err)
		}
		
		if matched {
			v.logDebug("OR condition passed on sub-condition type %s", subCondition.Type)
			return true, nil
		}
	}
	
	v.logDebug("OR condition failed with %d sub-conditions", len(condition.Conditions))
	return false, nil
}

type NotValidator struct {
	*BaseValidator
	registry *rules.ValidatorRegistry
}


func NewNotValidator(registry *rules.ValidatorRegistry, diagnostics bool) ConditionValidator {
	return &NotValidator{
		BaseValidator: NewBaseValidator(diagnostics),
		registry:      registry,
	}
}

func (v *NotValidator) Validate(condition models.Condition, ctx *rules.EvaluationContext) (bool, error) {
	if len(condition.Conditions) != 1 {
		return false, fmt.Errorf("NOT condition must have exactly one sub-condition")
	}
	
	subCondition := condition.Conditions[0]
	validator, err := v.registry.GetValidator(subCondition.Type)
	if err != nil {
		return false, fmt.Errorf("error getting validator for sub-condition: %w", err)
	}
	
	matched, err := validator.Validate(subCondition, ctx)
	if err != nil {
		return false, fmt.Errorf("error validating sub-condition: %w", err)
	}
	
	v.logDebug("NOT condition inverted result: !%v = %v", matched, !matched)
	return !matched, nil
}
package rules

import (
	"fmt"
	"log"
	"sync"

	"escalato/internal/models"
)


type ConditionValidator interface {
	Validate(condition models.Condition, ctx *EvaluationContext) (bool, error)
}


type ValidatorRegistry struct {
	validators  map[models.ConditionType]ConditionValidator
	mutex       sync.RWMutex
	diagnostics bool
}


func NewValidatorRegistry(diagnostics bool) *ValidatorRegistry {
	return &ValidatorRegistry{
		validators:  make(map[models.ConditionType]ConditionValidator),
		diagnostics: diagnostics,
	}
}

func (r *ValidatorRegistry) logDebug(format string, args ...interface{}) {
	if r.diagnostics {
		log.Printf("[REGISTRY] "+format, args...)
	}
}


func (r *ValidatorRegistry) RegisterValidator(conditionType models.ConditionType, validator ConditionValidator) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	
	r.validators[conditionType] = validator
	r.logDebug("Registered validator for condition type: %s", conditionType)
}


func (r *ValidatorRegistry) GetValidator(conditionType models.ConditionType) (ConditionValidator, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	
	validator, ok := r.validators[conditionType]
	if !ok {
		return nil, fmt.Errorf("no validator registered for condition type: %s", conditionType)
	}
	
	return validator, nil
}
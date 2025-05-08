package validator

import (
	"fmt"
	"time"

	"escalato/internal/models"
	"escalato/internal/rules"
)

// UnusedPermissionsValidator checks for unused permissions in roles
type UnusedPermissionsValidator struct {
	*BaseValidator
}

// NewUnusedPermissionsValidator creates a new validator for detecting unused permissions
func NewUnusedPermissionsValidator(diagnostics bool) ConditionValidator {
	return &UnusedPermissionsValidator{
		BaseValidator: NewBaseValidator(diagnostics),
	}
}

// Validate implements the ConditionValidator interface
func (v *UnusedPermissionsValidator) Validate(condition models.Condition, ctx *rules.EvaluationContext) (bool, error) {
	v.logDebug("Checking for unused permissions in resource %s", ctx.Resource.GetName())

	// This validator only works for roles
	if ctx.Resource.GetType() != string(models.RoleResource) {
		return false, nil
	}

	// Get the last used info
	lastUsedValue, exists := ctx.Resource.GetProperty("LastUsed")
	if !exists {
		v.logDebug("No LastUsed info found for resource %s", ctx.Resource.GetName())
		ctx.Data["unused_reason"] = "Role has never been used"
		return true, nil
	}

	// Check if LastUsed is null
	lastUsed, ok := lastUsedValue.(*models.RoleLastUsed)
	if !ok || lastUsed == nil {
		v.logDebug("LastUsed is null for resource %s", ctx.Resource.GetName())
		ctx.Data["unused_reason"] = "Role has never been used"
		return true, nil
	}

	// Check the threshold (days without usage)
	threshold := 90 // Default to 90 days
	if condition.Threshold > 0 {
		threshold = condition.Threshold
	}

	daysInactive := int(time.Since(lastUsed.Date).Hours() / 24)
	if daysInactive > threshold {
		v.logDebug("Role %s has not been used for %d days (threshold: %d)",
			ctx.Resource.GetName(), daysInactive, threshold)
		ctx.Data["days_inactive"] = daysInactive
		ctx.Data["unused_reason"] = fmt.Sprintf("Role has not been used for %d days", daysInactive)
		return true, nil
	}

	return false, nil
}

// Code generated by go-swagger; DO NOT EDIT.

package cli

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/isometry/go-digicert-mpki/models"
	"github.com/spf13/cobra"
)

// Schema cli for San

// register flags to command
func registerModelSanFlags(depth int, cmdPrefix string, cmd *cobra.Command) error {

	if err := registerSanAttributes(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerSanCritical(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	return nil
}

func registerSanAttributes(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	// warning: attributes []*Attribute array type is not supported by go-swagger cli yet

	return nil
}

func registerSanCritical(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	criticalDescription := ``

	var criticalFlagName string
	if cmdPrefix == "" {
		criticalFlagName = "critical"
	} else {
		criticalFlagName = fmt.Sprintf("%v.critical", cmdPrefix)
	}

	var criticalFlagDefault bool

	_ = cmd.PersistentFlags().Bool(criticalFlagName, criticalFlagDefault, criticalDescription)

	return nil
}

// retrieve flags from commands, and set value in model. Return true if any flag is passed by user to fill model field.
func retrieveModelSanFlags(depth int, m *models.San, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	retAdded := false

	err, attributesAdded := retrieveSanAttributesFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || attributesAdded

	err, criticalAdded := retrieveSanCriticalFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || criticalAdded

	return nil, retAdded
}

func retrieveSanAttributesFlags(depth int, m *models.San, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	attributesFlagName := fmt.Sprintf("%v.attributes", cmdPrefix)
	if cmd.Flags().Changed(attributesFlagName) {
		// warning: attributes array type []*Attribute is not supported by go-swagger cli yet
	}

	return nil, retAdded
}

func retrieveSanCriticalFlags(depth int, m *models.San, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	criticalFlagName := fmt.Sprintf("%v.critical", cmdPrefix)
	if cmd.Flags().Changed(criticalFlagName) {

		var criticalFlagName string
		if cmdPrefix == "" {
			criticalFlagName = "critical"
		} else {
			criticalFlagName = fmt.Sprintf("%v.critical", cmdPrefix)
		}

		criticalFlagValue, err := cmd.Flags().GetBool(criticalFlagName)
		if err != nil {
			return err, false
		}
		m.Critical = criticalFlagValue

		retAdded = true
	}

	return nil, retAdded
}

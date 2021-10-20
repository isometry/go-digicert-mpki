// Code generated by go-swagger; DO NOT EDIT.

package cli

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/isometry/go-digicert-mpki/models"
	"github.com/spf13/cobra"
)

// Schema cli for Authentication

// register flags to command
func registerModelAuthenticationFlags(depth int, cmdPrefix string, cmd *cobra.Command) error {

	if err := registerAuthenticationApproval(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerAuthenticationAttributes(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerAuthenticationMethod(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerAuthenticationMethodID(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	return nil
}

func registerAuthenticationApproval(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	approvalDescription := ``

	var approvalFlagName string
	if cmdPrefix == "" {
		approvalFlagName = "approval"
	} else {
		approvalFlagName = fmt.Sprintf("%v.approval", cmdPrefix)
	}

	var approvalFlagDefault string

	_ = cmd.PersistentFlags().String(approvalFlagName, approvalFlagDefault, approvalDescription)

	return nil
}

func registerAuthenticationAttributes(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	// warning: attributes []*AuthAttribute array type is not supported by go-swagger cli yet

	return nil
}

func registerAuthenticationMethod(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	methodDescription := ``

	var methodFlagName string
	if cmdPrefix == "" {
		methodFlagName = "method"
	} else {
		methodFlagName = fmt.Sprintf("%v.method", cmdPrefix)
	}

	var methodFlagDefault string

	_ = cmd.PersistentFlags().String(methodFlagName, methodFlagDefault, methodDescription)

	return nil
}

func registerAuthenticationMethodID(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	methodIdDescription := ``

	var methodIdFlagName string
	if cmdPrefix == "" {
		methodIdFlagName = "method_id"
	} else {
		methodIdFlagName = fmt.Sprintf("%v.method_id", cmdPrefix)
	}

	var methodIdFlagDefault string

	_ = cmd.PersistentFlags().String(methodIdFlagName, methodIdFlagDefault, methodIdDescription)

	return nil
}

// retrieve flags from commands, and set value in model. Return true if any flag is passed by user to fill model field.
func retrieveModelAuthenticationFlags(depth int, m *models.Authentication, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	retAdded := false

	err, approvalAdded := retrieveAuthenticationApprovalFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || approvalAdded

	err, attributesAdded := retrieveAuthenticationAttributesFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || attributesAdded

	err, methodAdded := retrieveAuthenticationMethodFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || methodAdded

	err, methodIdAdded := retrieveAuthenticationMethodIDFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || methodIdAdded

	return nil, retAdded
}

func retrieveAuthenticationApprovalFlags(depth int, m *models.Authentication, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	approvalFlagName := fmt.Sprintf("%v.approval", cmdPrefix)
	if cmd.Flags().Changed(approvalFlagName) {

		var approvalFlagName string
		if cmdPrefix == "" {
			approvalFlagName = "approval"
		} else {
			approvalFlagName = fmt.Sprintf("%v.approval", cmdPrefix)
		}

		approvalFlagValue, err := cmd.Flags().GetString(approvalFlagName)
		if err != nil {
			return err, false
		}
		m.Approval = approvalFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveAuthenticationAttributesFlags(depth int, m *models.Authentication, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	attributesFlagName := fmt.Sprintf("%v.attributes", cmdPrefix)
	if cmd.Flags().Changed(attributesFlagName) {
		// warning: attributes array type []*AuthAttribute is not supported by go-swagger cli yet
	}

	return nil, retAdded
}

func retrieveAuthenticationMethodFlags(depth int, m *models.Authentication, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	methodFlagName := fmt.Sprintf("%v.method", cmdPrefix)
	if cmd.Flags().Changed(methodFlagName) {

		var methodFlagName string
		if cmdPrefix == "" {
			methodFlagName = "method"
		} else {
			methodFlagName = fmt.Sprintf("%v.method", cmdPrefix)
		}

		methodFlagValue, err := cmd.Flags().GetString(methodFlagName)
		if err != nil {
			return err, false
		}
		m.Method = methodFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveAuthenticationMethodIDFlags(depth int, m *models.Authentication, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	methodIdFlagName := fmt.Sprintf("%v.method_id", cmdPrefix)
	if cmd.Flags().Changed(methodIdFlagName) {

		var methodIdFlagName string
		if cmdPrefix == "" {
			methodIdFlagName = "method_id"
		} else {
			methodIdFlagName = fmt.Sprintf("%v.method_id", cmdPrefix)
		}

		methodIdFlagValue, err := cmd.Flags().GetString(methodIdFlagName)
		if err != nil {
			return err, false
		}
		m.MethodID = methodIdFlagValue

		retAdded = true
	}

	return nil, retAdded
}
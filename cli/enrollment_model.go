// Code generated by go-swagger; DO NOT EDIT.

package cli

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/isometry/go-digicert-mpki/models"
	"github.com/spf13/cobra"
)

// Schema cli for Enrollment

// register flags to command
func registerModelEnrollmentFlags(depth int, cmdPrefix string, cmd *cobra.Command) error {

	if err := registerEnrollmentClientType(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerEnrollmentClientTypeID(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	return nil
}

func registerEnrollmentClientType(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	clientTypeDescription := ``

	var clientTypeFlagName string
	if cmdPrefix == "" {
		clientTypeFlagName = "client_type"
	} else {
		clientTypeFlagName = fmt.Sprintf("%v.client_type", cmdPrefix)
	}

	var clientTypeFlagDefault string

	_ = cmd.PersistentFlags().String(clientTypeFlagName, clientTypeFlagDefault, clientTypeDescription)

	return nil
}

func registerEnrollmentClientTypeID(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	clientTypeIdDescription := ``

	var clientTypeIdFlagName string
	if cmdPrefix == "" {
		clientTypeIdFlagName = "client_type_id"
	} else {
		clientTypeIdFlagName = fmt.Sprintf("%v.client_type_id", cmdPrefix)
	}

	var clientTypeIdFlagDefault string

	_ = cmd.PersistentFlags().String(clientTypeIdFlagName, clientTypeIdFlagDefault, clientTypeIdDescription)

	return nil
}

// retrieve flags from commands, and set value in model. Return true if any flag is passed by user to fill model field.
func retrieveModelEnrollmentFlags(depth int, m *models.Enrollment, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	retAdded := false

	err, clientTypeAdded := retrieveEnrollmentClientTypeFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || clientTypeAdded

	err, clientTypeIdAdded := retrieveEnrollmentClientTypeIDFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || clientTypeIdAdded

	return nil, retAdded
}

func retrieveEnrollmentClientTypeFlags(depth int, m *models.Enrollment, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	clientTypeFlagName := fmt.Sprintf("%v.client_type", cmdPrefix)
	if cmd.Flags().Changed(clientTypeFlagName) {

		var clientTypeFlagName string
		if cmdPrefix == "" {
			clientTypeFlagName = "client_type"
		} else {
			clientTypeFlagName = fmt.Sprintf("%v.client_type", cmdPrefix)
		}

		clientTypeFlagValue, err := cmd.Flags().GetString(clientTypeFlagName)
		if err != nil {
			return err, false
		}
		m.ClientType = clientTypeFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveEnrollmentClientTypeIDFlags(depth int, m *models.Enrollment, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	clientTypeIdFlagName := fmt.Sprintf("%v.client_type_id", cmdPrefix)
	if cmd.Flags().Changed(clientTypeIdFlagName) {

		var clientTypeIdFlagName string
		if cmdPrefix == "" {
			clientTypeIdFlagName = "client_type_id"
		} else {
			clientTypeIdFlagName = fmt.Sprintf("%v.client_type_id", cmdPrefix)
		}

		clientTypeIdFlagValue, err := cmd.Flags().GetString(clientTypeIdFlagName)
		if err != nil {
			return err, false
		}
		m.ClientTypeID = clientTypeIdFlagValue

		retAdded = true
	}

	return nil, retAdded
}

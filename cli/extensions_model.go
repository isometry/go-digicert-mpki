// Code generated by go-swagger; DO NOT EDIT.

package cli

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/swag"
	"github.com/isometry/go-digicert-mpki/models"

	"github.com/spf13/cobra"
)

// Schema cli for Extensions

// register flags to command
func registerModelExtensionsFlags(depth int, cmdPrefix string, cmd *cobra.Command) error {

	if err := registerExtensionsSan(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	return nil
}

func registerExtensionsSan(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	var sanFlagName string
	if cmdPrefix == "" {
		sanFlagName = "san"
	} else {
		sanFlagName = fmt.Sprintf("%v.san", cmdPrefix)
	}

	if err := registerModelSanFlags(depth+1, sanFlagName, cmd); err != nil {
		return err
	}

	return nil
}

// retrieve flags from commands, and set value in model. Return true if any flag is passed by user to fill model field.
func retrieveModelExtensionsFlags(depth int, m *models.Extensions, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	retAdded := false

	err, sanAdded := retrieveExtensionsSanFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || sanAdded

	return nil, retAdded
}

func retrieveExtensionsSanFlags(depth int, m *models.Extensions, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	sanFlagName := fmt.Sprintf("%v.san", cmdPrefix)
	if cmd.Flags().Changed(sanFlagName) {
		// info: complex object san San is retrieved outside this Changed() block
	}
	sanFlagValue := m.San
	if swag.IsZero(sanFlagValue) {
		sanFlagValue = &models.San{}
	}

	err, sanAdded := retrieveModelSanFlags(depth+1, sanFlagValue, sanFlagName, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || sanAdded
	if sanAdded {
		m.San = sanFlagValue
	}

	return nil, retAdded
}

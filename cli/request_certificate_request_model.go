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

// Schema cli for RequestCertificateRequest

// register flags to command
func registerModelRequestCertificateRequestFlags(depth int, cmdPrefix string, cmd *cobra.Command) error {

	if err := registerRequestCertificateRequestAttributes(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerRequestCertificateRequestAuthentication(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerRequestCertificateRequestCsr(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerRequestCertificateRequestProfile(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerRequestCertificateRequestSeat(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerRequestCertificateRequestSessionKey(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerRequestCertificateRequestValidity(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	return nil
}

func registerRequestCertificateRequestAttributes(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	var attributesFlagName string
	if cmdPrefix == "" {
		attributesFlagName = "attributes"
	} else {
		attributesFlagName = fmt.Sprintf("%v.attributes", cmdPrefix)
	}

	if err := registerModelCertificateAttributesFlags(depth+1, attributesFlagName, cmd); err != nil {
		return err
	}

	return nil
}

func registerRequestCertificateRequestAuthentication(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	// warning: authentication map[string]string map type is not supported by go-swagger cli yet

	return nil
}

func registerRequestCertificateRequestCsr(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	csrDescription := ``

	var csrFlagName string
	if cmdPrefix == "" {
		csrFlagName = "csr"
	} else {
		csrFlagName = fmt.Sprintf("%v.csr", cmdPrefix)
	}

	var csrFlagDefault string

	_ = cmd.PersistentFlags().String(csrFlagName, csrFlagDefault, csrDescription)

	return nil
}

func registerRequestCertificateRequestProfile(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	var profileFlagName string
	if cmdPrefix == "" {
		profileFlagName = "profile"
	} else {
		profileFlagName = fmt.Sprintf("%v.profile", cmdPrefix)
	}

	if err := registerModelProfileFlags(depth+1, profileFlagName, cmd); err != nil {
		return err
	}

	return nil
}

func registerRequestCertificateRequestSeat(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	var seatFlagName string
	if cmdPrefix == "" {
		seatFlagName = "seat"
	} else {
		seatFlagName = fmt.Sprintf("%v.seat", cmdPrefix)
	}

	if err := registerModelSeatFlags(depth+1, seatFlagName, cmd); err != nil {
		return err
	}

	return nil
}

func registerRequestCertificateRequestSessionKey(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	sessionKeyDescription := ``

	var sessionKeyFlagName string
	if cmdPrefix == "" {
		sessionKeyFlagName = "session_key"
	} else {
		sessionKeyFlagName = fmt.Sprintf("%v.session_key", cmdPrefix)
	}

	var sessionKeyFlagDefault string

	_ = cmd.PersistentFlags().String(sessionKeyFlagName, sessionKeyFlagDefault, sessionKeyDescription)

	return nil
}

func registerRequestCertificateRequestValidity(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	var validityFlagName string
	if cmdPrefix == "" {
		validityFlagName = "validity"
	} else {
		validityFlagName = fmt.Sprintf("%v.validity", cmdPrefix)
	}

	if err := registerModelValidityFlags(depth+1, validityFlagName, cmd); err != nil {
		return err
	}

	return nil
}

// retrieve flags from commands, and set value in model. Return true if any flag is passed by user to fill model field.
func retrieveModelRequestCertificateRequestFlags(depth int, m *models.RequestCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	retAdded := false

	err, attributesAdded := retrieveRequestCertificateRequestAttributesFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || attributesAdded

	err, authenticationAdded := retrieveRequestCertificateRequestAuthenticationFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || authenticationAdded

	err, csrAdded := retrieveRequestCertificateRequestCsrFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || csrAdded

	err, profileAdded := retrieveRequestCertificateRequestProfileFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || profileAdded

	err, seatAdded := retrieveRequestCertificateRequestSeatFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || seatAdded

	err, sessionKeyAdded := retrieveRequestCertificateRequestSessionKeyFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || sessionKeyAdded

	err, validityAdded := retrieveRequestCertificateRequestValidityFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || validityAdded

	return nil, retAdded
}

func retrieveRequestCertificateRequestAttributesFlags(depth int, m *models.RequestCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	attributesFlagName := fmt.Sprintf("%v.attributes", cmdPrefix)
	if cmd.Flags().Changed(attributesFlagName) {
		// info: complex object attributes CertificateAttributes is retrieved outside this Changed() block
	}
	attributesFlagValue := m.Attributes
	if swag.IsZero(attributesFlagValue) {
		attributesFlagValue = &models.CertificateAttributes{}
	}

	err, attributesAdded := retrieveModelCertificateAttributesFlags(depth+1, attributesFlagValue, attributesFlagName, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || attributesAdded
	if attributesAdded {
		m.Attributes = attributesFlagValue
	}

	return nil, retAdded
}

func retrieveRequestCertificateRequestAuthenticationFlags(depth int, m *models.RequestCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	authenticationFlagName := fmt.Sprintf("%v.authentication", cmdPrefix)
	if cmd.Flags().Changed(authenticationFlagName) {
		// warning: authentication map type map[string]string is not supported by go-swagger cli yet
	}

	return nil, retAdded
}

func retrieveRequestCertificateRequestCsrFlags(depth int, m *models.RequestCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	csrFlagName := fmt.Sprintf("%v.csr", cmdPrefix)
	if cmd.Flags().Changed(csrFlagName) {

		var csrFlagName string
		if cmdPrefix == "" {
			csrFlagName = "csr"
		} else {
			csrFlagName = fmt.Sprintf("%v.csr", cmdPrefix)
		}

		csrFlagValue, err := cmd.Flags().GetString(csrFlagName)
		if err != nil {
			return err, false
		}
		m.Csr = csrFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveRequestCertificateRequestProfileFlags(depth int, m *models.RequestCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	profileFlagName := fmt.Sprintf("%v.profile", cmdPrefix)
	if cmd.Flags().Changed(profileFlagName) {
		// info: complex object profile Profile is retrieved outside this Changed() block
	}
	profileFlagValue := m.Profile
	if swag.IsZero(profileFlagValue) {
		profileFlagValue = &models.Profile{}
	}

	err, profileAdded := retrieveModelProfileFlags(depth+1, profileFlagValue, profileFlagName, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || profileAdded
	if profileAdded {
		m.Profile = profileFlagValue
	}

	return nil, retAdded
}

func retrieveRequestCertificateRequestSeatFlags(depth int, m *models.RequestCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	seatFlagName := fmt.Sprintf("%v.seat", cmdPrefix)
	if cmd.Flags().Changed(seatFlagName) {
		// info: complex object seat Seat is retrieved outside this Changed() block
	}
	seatFlagValue := m.Seat
	if swag.IsZero(seatFlagValue) {
		seatFlagValue = &models.Seat{}
	}

	err, seatAdded := retrieveModelSeatFlags(depth+1, seatFlagValue, seatFlagName, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || seatAdded
	if seatAdded {
		m.Seat = seatFlagValue
	}

	return nil, retAdded
}

func retrieveRequestCertificateRequestSessionKeyFlags(depth int, m *models.RequestCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	sessionKeyFlagName := fmt.Sprintf("%v.session_key", cmdPrefix)
	if cmd.Flags().Changed(sessionKeyFlagName) {

		var sessionKeyFlagName string
		if cmdPrefix == "" {
			sessionKeyFlagName = "session_key"
		} else {
			sessionKeyFlagName = fmt.Sprintf("%v.session_key", cmdPrefix)
		}

		sessionKeyFlagValue, err := cmd.Flags().GetString(sessionKeyFlagName)
		if err != nil {
			return err, false
		}
		m.SessionKey = sessionKeyFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveRequestCertificateRequestValidityFlags(depth int, m *models.RequestCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	validityFlagName := fmt.Sprintf("%v.validity", cmdPrefix)
	if cmd.Flags().Changed(validityFlagName) {
		// info: complex object validity Validity is retrieved outside this Changed() block
	}
	validityFlagValue := m.Validity
	if swag.IsZero(validityFlagValue) {
		validityFlagValue = &models.Validity{}
	}

	err, validityAdded := retrieveModelValidityFlags(depth+1, validityFlagValue, validityFlagName, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || validityAdded
	if validityAdded {
		m.Validity = validityFlagValue
	}

	return nil, retAdded
}

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

// Schema cli for GetCertificateResponse

// register flags to command
func registerModelGetCertificateResponseFlags(depth int, cmdPrefix string, cmd *cobra.Command) error {

	if err := registerGetCertificateResponseAccount(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetCertificateResponseCertificate(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetCertificateResponseCommonName(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetCertificateResponseEnrollmentNotes(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetCertificateResponseIsKeyEscrowed(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetCertificateResponsePassword(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetCertificateResponseProfile(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetCertificateResponseRevocation(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetCertificateResponseSeat(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetCertificateResponseSerialNumber(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetCertificateResponseSessionKey(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetCertificateResponseStatus(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetCertificateResponseValidFrom(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetCertificateResponseValidTo(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetCertificateResponseWebpin(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	return nil
}

func registerGetCertificateResponseAccount(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	var accountFlagName string
	if cmdPrefix == "" {
		accountFlagName = "account"
	} else {
		accountFlagName = fmt.Sprintf("%v.account", cmdPrefix)
	}

	if err := registerModelAccountFlags(depth+1, accountFlagName, cmd); err != nil {
		return err
	}

	return nil
}

func registerGetCertificateResponseCertificate(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	certificateDescription := ``

	var certificateFlagName string
	if cmdPrefix == "" {
		certificateFlagName = "certificate"
	} else {
		certificateFlagName = fmt.Sprintf("%v.certificate", cmdPrefix)
	}

	var certificateFlagDefault string

	_ = cmd.PersistentFlags().String(certificateFlagName, certificateFlagDefault, certificateDescription)

	return nil
}

func registerGetCertificateResponseCommonName(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	commonNameDescription := ``

	var commonNameFlagName string
	if cmdPrefix == "" {
		commonNameFlagName = "common_name"
	} else {
		commonNameFlagName = fmt.Sprintf("%v.common_name", cmdPrefix)
	}

	var commonNameFlagDefault string

	_ = cmd.PersistentFlags().String(commonNameFlagName, commonNameFlagDefault, commonNameDescription)

	return nil
}

func registerGetCertificateResponseEnrollmentNotes(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	enrollmentNotesDescription := ``

	var enrollmentNotesFlagName string
	if cmdPrefix == "" {
		enrollmentNotesFlagName = "enrollment_notes"
	} else {
		enrollmentNotesFlagName = fmt.Sprintf("%v.enrollment_notes", cmdPrefix)
	}

	var enrollmentNotesFlagDefault string

	_ = cmd.PersistentFlags().String(enrollmentNotesFlagName, enrollmentNotesFlagDefault, enrollmentNotesDescription)

	return nil
}

func registerGetCertificateResponseIsKeyEscrowed(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	isKeyEscrowedDescription := ``

	var isKeyEscrowedFlagName string
	if cmdPrefix == "" {
		isKeyEscrowedFlagName = "is_key_escrowed"
	} else {
		isKeyEscrowedFlagName = fmt.Sprintf("%v.is_key_escrowed", cmdPrefix)
	}

	var isKeyEscrowedFlagDefault bool

	_ = cmd.PersistentFlags().Bool(isKeyEscrowedFlagName, isKeyEscrowedFlagDefault, isKeyEscrowedDescription)

	return nil
}

func registerGetCertificateResponsePassword(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	passwordDescription := ``

	var passwordFlagName string
	if cmdPrefix == "" {
		passwordFlagName = "password"
	} else {
		passwordFlagName = fmt.Sprintf("%v.password", cmdPrefix)
	}

	var passwordFlagDefault string

	_ = cmd.PersistentFlags().String(passwordFlagName, passwordFlagDefault, passwordDescription)

	return nil
}

func registerGetCertificateResponseProfile(depth int, cmdPrefix string, cmd *cobra.Command) error {
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

func registerGetCertificateResponseRevocation(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	var revocationFlagName string
	if cmdPrefix == "" {
		revocationFlagName = "revocation"
	} else {
		revocationFlagName = fmt.Sprintf("%v.revocation", cmdPrefix)
	}

	if err := registerModelRevocationFlags(depth+1, revocationFlagName, cmd); err != nil {
		return err
	}

	return nil
}

func registerGetCertificateResponseSeat(depth int, cmdPrefix string, cmd *cobra.Command) error {
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

func registerGetCertificateResponseSerialNumber(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	serialNumberDescription := ``

	var serialNumberFlagName string
	if cmdPrefix == "" {
		serialNumberFlagName = "serial_number"
	} else {
		serialNumberFlagName = fmt.Sprintf("%v.serial_number", cmdPrefix)
	}

	var serialNumberFlagDefault string

	_ = cmd.PersistentFlags().String(serialNumberFlagName, serialNumberFlagDefault, serialNumberDescription)

	return nil
}

func registerGetCertificateResponseSessionKey(depth int, cmdPrefix string, cmd *cobra.Command) error {
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

func registerGetCertificateResponseStatus(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	statusDescription := ``

	var statusFlagName string
	if cmdPrefix == "" {
		statusFlagName = "status"
	} else {
		statusFlagName = fmt.Sprintf("%v.status", cmdPrefix)
	}

	var statusFlagDefault string

	_ = cmd.PersistentFlags().String(statusFlagName, statusFlagDefault, statusDescription)

	return nil
}

func registerGetCertificateResponseValidFrom(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	validFromDescription := ``

	var validFromFlagName string
	if cmdPrefix == "" {
		validFromFlagName = "valid_from"
	} else {
		validFromFlagName = fmt.Sprintf("%v.valid_from", cmdPrefix)
	}

	var validFromFlagDefault string

	_ = cmd.PersistentFlags().String(validFromFlagName, validFromFlagDefault, validFromDescription)

	return nil
}

func registerGetCertificateResponseValidTo(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	validToDescription := ``

	var validToFlagName string
	if cmdPrefix == "" {
		validToFlagName = "valid_to"
	} else {
		validToFlagName = fmt.Sprintf("%v.valid_to", cmdPrefix)
	}

	var validToFlagDefault string

	_ = cmd.PersistentFlags().String(validToFlagName, validToFlagDefault, validToDescription)

	return nil
}

func registerGetCertificateResponseWebpin(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	webpinDescription := ``

	var webpinFlagName string
	if cmdPrefix == "" {
		webpinFlagName = "webpin"
	} else {
		webpinFlagName = fmt.Sprintf("%v.webpin", cmdPrefix)
	}

	var webpinFlagDefault string

	_ = cmd.PersistentFlags().String(webpinFlagName, webpinFlagDefault, webpinDescription)

	return nil
}

// retrieve flags from commands, and set value in model. Return true if any flag is passed by user to fill model field.
func retrieveModelGetCertificateResponseFlags(depth int, m *models.GetCertificateResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	retAdded := false

	err, accountAdded := retrieveGetCertificateResponseAccountFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || accountAdded

	err, certificateAdded := retrieveGetCertificateResponseCertificateFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || certificateAdded

	err, commonNameAdded := retrieveGetCertificateResponseCommonNameFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || commonNameAdded

	err, enrollmentNotesAdded := retrieveGetCertificateResponseEnrollmentNotesFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || enrollmentNotesAdded

	err, isKeyEscrowedAdded := retrieveGetCertificateResponseIsKeyEscrowedFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || isKeyEscrowedAdded

	err, passwordAdded := retrieveGetCertificateResponsePasswordFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || passwordAdded

	err, profileAdded := retrieveGetCertificateResponseProfileFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || profileAdded

	err, revocationAdded := retrieveGetCertificateResponseRevocationFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || revocationAdded

	err, seatAdded := retrieveGetCertificateResponseSeatFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || seatAdded

	err, serialNumberAdded := retrieveGetCertificateResponseSerialNumberFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || serialNumberAdded

	err, sessionKeyAdded := retrieveGetCertificateResponseSessionKeyFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || sessionKeyAdded

	err, statusAdded := retrieveGetCertificateResponseStatusFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || statusAdded

	err, validFromAdded := retrieveGetCertificateResponseValidFromFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || validFromAdded

	err, validToAdded := retrieveGetCertificateResponseValidToFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || validToAdded

	err, webpinAdded := retrieveGetCertificateResponseWebpinFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || webpinAdded

	return nil, retAdded
}

func retrieveGetCertificateResponseAccountFlags(depth int, m *models.GetCertificateResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	accountFlagName := fmt.Sprintf("%v.account", cmdPrefix)
	if cmd.Flags().Changed(accountFlagName) {
		// info: complex object account Account is retrieved outside this Changed() block
	}
	accountFlagValue := m.Account
	if swag.IsZero(accountFlagValue) {
		accountFlagValue = &models.Account{}
	}

	err, accountAdded := retrieveModelAccountFlags(depth+1, accountFlagValue, accountFlagName, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || accountAdded
	if accountAdded {
		m.Account = accountFlagValue
	}

	return nil, retAdded
}

func retrieveGetCertificateResponseCertificateFlags(depth int, m *models.GetCertificateResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	certificateFlagName := fmt.Sprintf("%v.certificate", cmdPrefix)
	if cmd.Flags().Changed(certificateFlagName) {

		var certificateFlagName string
		if cmdPrefix == "" {
			certificateFlagName = "certificate"
		} else {
			certificateFlagName = fmt.Sprintf("%v.certificate", cmdPrefix)
		}

		certificateFlagValue, err := cmd.Flags().GetString(certificateFlagName)
		if err != nil {
			return err, false
		}
		m.Certificate = certificateFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveGetCertificateResponseCommonNameFlags(depth int, m *models.GetCertificateResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	commonNameFlagName := fmt.Sprintf("%v.common_name", cmdPrefix)
	if cmd.Flags().Changed(commonNameFlagName) {

		var commonNameFlagName string
		if cmdPrefix == "" {
			commonNameFlagName = "common_name"
		} else {
			commonNameFlagName = fmt.Sprintf("%v.common_name", cmdPrefix)
		}

		commonNameFlagValue, err := cmd.Flags().GetString(commonNameFlagName)
		if err != nil {
			return err, false
		}
		m.CommonName = commonNameFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveGetCertificateResponseEnrollmentNotesFlags(depth int, m *models.GetCertificateResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	enrollmentNotesFlagName := fmt.Sprintf("%v.enrollment_notes", cmdPrefix)
	if cmd.Flags().Changed(enrollmentNotesFlagName) {

		var enrollmentNotesFlagName string
		if cmdPrefix == "" {
			enrollmentNotesFlagName = "enrollment_notes"
		} else {
			enrollmentNotesFlagName = fmt.Sprintf("%v.enrollment_notes", cmdPrefix)
		}

		enrollmentNotesFlagValue, err := cmd.Flags().GetString(enrollmentNotesFlagName)
		if err != nil {
			return err, false
		}
		m.EnrollmentNotes = enrollmentNotesFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveGetCertificateResponseIsKeyEscrowedFlags(depth int, m *models.GetCertificateResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	isKeyEscrowedFlagName := fmt.Sprintf("%v.is_key_escrowed", cmdPrefix)
	if cmd.Flags().Changed(isKeyEscrowedFlagName) {

		var isKeyEscrowedFlagName string
		if cmdPrefix == "" {
			isKeyEscrowedFlagName = "is_key_escrowed"
		} else {
			isKeyEscrowedFlagName = fmt.Sprintf("%v.is_key_escrowed", cmdPrefix)
		}

		isKeyEscrowedFlagValue, err := cmd.Flags().GetBool(isKeyEscrowedFlagName)
		if err != nil {
			return err, false
		}
		m.IsKeyEscrowed = isKeyEscrowedFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveGetCertificateResponsePasswordFlags(depth int, m *models.GetCertificateResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	passwordFlagName := fmt.Sprintf("%v.password", cmdPrefix)
	if cmd.Flags().Changed(passwordFlagName) {

		var passwordFlagName string
		if cmdPrefix == "" {
			passwordFlagName = "password"
		} else {
			passwordFlagName = fmt.Sprintf("%v.password", cmdPrefix)
		}

		passwordFlagValue, err := cmd.Flags().GetString(passwordFlagName)
		if err != nil {
			return err, false
		}
		m.Password = passwordFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveGetCertificateResponseProfileFlags(depth int, m *models.GetCertificateResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
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

func retrieveGetCertificateResponseRevocationFlags(depth int, m *models.GetCertificateResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	revocationFlagName := fmt.Sprintf("%v.revocation", cmdPrefix)
	if cmd.Flags().Changed(revocationFlagName) {
		// info: complex object revocation Revocation is retrieved outside this Changed() block
	}
	revocationFlagValue := m.Revocation
	if swag.IsZero(revocationFlagValue) {
		revocationFlagValue = &models.Revocation{}
	}

	err, revocationAdded := retrieveModelRevocationFlags(depth+1, revocationFlagValue, revocationFlagName, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || revocationAdded
	if revocationAdded {
		m.Revocation = revocationFlagValue
	}

	return nil, retAdded
}

func retrieveGetCertificateResponseSeatFlags(depth int, m *models.GetCertificateResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
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

func retrieveGetCertificateResponseSerialNumberFlags(depth int, m *models.GetCertificateResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	serialNumberFlagName := fmt.Sprintf("%v.serial_number", cmdPrefix)
	if cmd.Flags().Changed(serialNumberFlagName) {

		var serialNumberFlagName string
		if cmdPrefix == "" {
			serialNumberFlagName = "serial_number"
		} else {
			serialNumberFlagName = fmt.Sprintf("%v.serial_number", cmdPrefix)
		}

		serialNumberFlagValue, err := cmd.Flags().GetString(serialNumberFlagName)
		if err != nil {
			return err, false
		}
		m.SerialNumber = serialNumberFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveGetCertificateResponseSessionKeyFlags(depth int, m *models.GetCertificateResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
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

func retrieveGetCertificateResponseStatusFlags(depth int, m *models.GetCertificateResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	statusFlagName := fmt.Sprintf("%v.status", cmdPrefix)
	if cmd.Flags().Changed(statusFlagName) {

		var statusFlagName string
		if cmdPrefix == "" {
			statusFlagName = "status"
		} else {
			statusFlagName = fmt.Sprintf("%v.status", cmdPrefix)
		}

		statusFlagValue, err := cmd.Flags().GetString(statusFlagName)
		if err != nil {
			return err, false
		}
		m.Status = statusFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveGetCertificateResponseValidFromFlags(depth int, m *models.GetCertificateResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	validFromFlagName := fmt.Sprintf("%v.valid_from", cmdPrefix)
	if cmd.Flags().Changed(validFromFlagName) {

		var validFromFlagName string
		if cmdPrefix == "" {
			validFromFlagName = "valid_from"
		} else {
			validFromFlagName = fmt.Sprintf("%v.valid_from", cmdPrefix)
		}

		validFromFlagValue, err := cmd.Flags().GetString(validFromFlagName)
		if err != nil {
			return err, false
		}
		m.ValidFrom = validFromFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveGetCertificateResponseValidToFlags(depth int, m *models.GetCertificateResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	validToFlagName := fmt.Sprintf("%v.valid_to", cmdPrefix)
	if cmd.Flags().Changed(validToFlagName) {

		var validToFlagName string
		if cmdPrefix == "" {
			validToFlagName = "valid_to"
		} else {
			validToFlagName = fmt.Sprintf("%v.valid_to", cmdPrefix)
		}

		validToFlagValue, err := cmd.Flags().GetString(validToFlagName)
		if err != nil {
			return err, false
		}
		m.ValidTo = validToFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveGetCertificateResponseWebpinFlags(depth int, m *models.GetCertificateResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	webpinFlagName := fmt.Sprintf("%v.webpin", cmdPrefix)
	if cmd.Flags().Changed(webpinFlagName) {

		var webpinFlagName string
		if cmdPrefix == "" {
			webpinFlagName = "webpin"
		} else {
			webpinFlagName = fmt.Sprintf("%v.webpin", cmdPrefix)
		}

		webpinFlagValue, err := cmd.Flags().GetString(webpinFlagName)
		if err != nil {
			return err, false
		}
		m.Webpin = webpinFlagValue

		retAdded = true
	}

	return nil, retAdded
}

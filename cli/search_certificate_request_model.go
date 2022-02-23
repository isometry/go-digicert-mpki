// Code generated by go-swagger; DO NOT EDIT.

package cli

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/isometry/go-digicert-mpki/models"
	"github.com/spf13/cobra"
)

// Schema cli for SearchCertificateRequest

// register flags to command
func RegisterModelSearchCertificateRequestFlags(depth int, cmdPrefix string, cmd *cobra.Command) error {

	if err := registerSearchCertificateRequestCommonName(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerSearchCertificateRequestEmail(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerSearchCertificateRequestIssuingCa(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerSearchCertificateRequestProfileID(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerSearchCertificateRequestSeatID(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerSearchCertificateRequestSerialNumber(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerSearchCertificateRequestStartIndex(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerSearchCertificateRequestStatus(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerSearchCertificateRequestValidFrom(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerSearchCertificateRequestValidTo(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	return nil
}

func registerSearchCertificateRequestCommonName(depth int, cmdPrefix string, cmd *cobra.Command) error {
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

func registerSearchCertificateRequestEmail(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	emailDescription := ``

	var emailFlagName string
	if cmdPrefix == "" {
		emailFlagName = "email"
	} else {
		emailFlagName = fmt.Sprintf("%v.email", cmdPrefix)
	}

	var emailFlagDefault string

	_ = cmd.PersistentFlags().String(emailFlagName, emailFlagDefault, emailDescription)

	return nil
}

func registerSearchCertificateRequestIssuingCa(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	issuingCaDescription := ``

	var issuingCaFlagName string
	if cmdPrefix == "" {
		issuingCaFlagName = "issuing_ca"
	} else {
		issuingCaFlagName = fmt.Sprintf("%v.issuing_ca", cmdPrefix)
	}

	var issuingCaFlagDefault string

	_ = cmd.PersistentFlags().String(issuingCaFlagName, issuingCaFlagDefault, issuingCaDescription)

	return nil
}

func registerSearchCertificateRequestProfileID(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	profileIdDescription := ``

	var profileIdFlagName string
	if cmdPrefix == "" {
		profileIdFlagName = "profile_id"
	} else {
		profileIdFlagName = fmt.Sprintf("%v.profile_id", cmdPrefix)
	}

	var profileIdFlagDefault string

	_ = cmd.PersistentFlags().String(profileIdFlagName, profileIdFlagDefault, profileIdDescription)

	return nil
}

func registerSearchCertificateRequestSeatID(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	seatIdDescription := ``

	var seatIdFlagName string
	if cmdPrefix == "" {
		seatIdFlagName = "seat_id"
	} else {
		seatIdFlagName = fmt.Sprintf("%v.seat_id", cmdPrefix)
	}

	var seatIdFlagDefault string

	_ = cmd.PersistentFlags().String(seatIdFlagName, seatIdFlagDefault, seatIdDescription)

	return nil
}

func registerSearchCertificateRequestSerialNumber(depth int, cmdPrefix string, cmd *cobra.Command) error {
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

func registerSearchCertificateRequestStartIndex(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	startIndexDescription := ``

	var startIndexFlagName string
	if cmdPrefix == "" {
		startIndexFlagName = "start_index"
	} else {
		startIndexFlagName = fmt.Sprintf("%v.start_index", cmdPrefix)
	}

	var startIndexFlagDefault int32

	_ = cmd.PersistentFlags().Int32(startIndexFlagName, startIndexFlagDefault, startIndexDescription)

	return nil
}

func registerSearchCertificateRequestStatus(depth int, cmdPrefix string, cmd *cobra.Command) error {
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

func registerSearchCertificateRequestValidFrom(depth int, cmdPrefix string, cmd *cobra.Command) error {
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

func registerSearchCertificateRequestValidTo(depth int, cmdPrefix string, cmd *cobra.Command) error {
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

// retrieve flags from commands, and set value in model. Return true if any flag is passed by user to fill model field.
func retrieveModelSearchCertificateRequestFlags(depth int, m *models.SearchCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	retAdded := false

	err, commonNameAdded := retrieveSearchCertificateRequestCommonNameFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || commonNameAdded

	err, emailAdded := retrieveSearchCertificateRequestEmailFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || emailAdded

	err, issuingCaAdded := retrieveSearchCertificateRequestIssuingCaFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || issuingCaAdded

	err, profileIdAdded := retrieveSearchCertificateRequestProfileIDFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || profileIdAdded

	err, seatIdAdded := retrieveSearchCertificateRequestSeatIDFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || seatIdAdded

	err, serialNumberAdded := retrieveSearchCertificateRequestSerialNumberFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || serialNumberAdded

	err, startIndexAdded := retrieveSearchCertificateRequestStartIndexFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || startIndexAdded

	err, statusAdded := retrieveSearchCertificateRequestStatusFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || statusAdded

	err, validFromAdded := retrieveSearchCertificateRequestValidFromFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || validFromAdded

	err, validToAdded := retrieveSearchCertificateRequestValidToFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || validToAdded

	return nil, retAdded
}

func retrieveSearchCertificateRequestCommonNameFlags(depth int, m *models.SearchCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
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

func retrieveSearchCertificateRequestEmailFlags(depth int, m *models.SearchCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	emailFlagName := fmt.Sprintf("%v.email", cmdPrefix)
	if cmd.Flags().Changed(emailFlagName) {

		var emailFlagName string
		if cmdPrefix == "" {
			emailFlagName = "email"
		} else {
			emailFlagName = fmt.Sprintf("%v.email", cmdPrefix)
		}

		emailFlagValue, err := cmd.Flags().GetString(emailFlagName)
		if err != nil {
			return err, false
		}
		m.Email = emailFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveSearchCertificateRequestIssuingCaFlags(depth int, m *models.SearchCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	issuingCaFlagName := fmt.Sprintf("%v.issuing_ca", cmdPrefix)
	if cmd.Flags().Changed(issuingCaFlagName) {

		var issuingCaFlagName string
		if cmdPrefix == "" {
			issuingCaFlagName = "issuing_ca"
		} else {
			issuingCaFlagName = fmt.Sprintf("%v.issuing_ca", cmdPrefix)
		}

		issuingCaFlagValue, err := cmd.Flags().GetString(issuingCaFlagName)
		if err != nil {
			return err, false
		}
		m.IssuingCa = issuingCaFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveSearchCertificateRequestProfileIDFlags(depth int, m *models.SearchCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	profileIdFlagName := fmt.Sprintf("%v.profile_id", cmdPrefix)
	if cmd.Flags().Changed(profileIdFlagName) {

		var profileIdFlagName string
		if cmdPrefix == "" {
			profileIdFlagName = "profile_id"
		} else {
			profileIdFlagName = fmt.Sprintf("%v.profile_id", cmdPrefix)
		}

		profileIdFlagValue, err := cmd.Flags().GetString(profileIdFlagName)
		if err != nil {
			return err, false
		}
		m.ProfileID = profileIdFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveSearchCertificateRequestSeatIDFlags(depth int, m *models.SearchCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	seatIdFlagName := fmt.Sprintf("%v.seat_id", cmdPrefix)
	if cmd.Flags().Changed(seatIdFlagName) {

		var seatIdFlagName string
		if cmdPrefix == "" {
			seatIdFlagName = "seat_id"
		} else {
			seatIdFlagName = fmt.Sprintf("%v.seat_id", cmdPrefix)
		}

		seatIdFlagValue, err := cmd.Flags().GetString(seatIdFlagName)
		if err != nil {
			return err, false
		}
		m.SeatID = seatIdFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveSearchCertificateRequestSerialNumberFlags(depth int, m *models.SearchCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
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

func retrieveSearchCertificateRequestStartIndexFlags(depth int, m *models.SearchCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	startIndexFlagName := fmt.Sprintf("%v.start_index", cmdPrefix)
	if cmd.Flags().Changed(startIndexFlagName) {

		var startIndexFlagName string
		if cmdPrefix == "" {
			startIndexFlagName = "start_index"
		} else {
			startIndexFlagName = fmt.Sprintf("%v.start_index", cmdPrefix)
		}

		startIndexFlagValue, err := cmd.Flags().GetInt32(startIndexFlagName)
		if err != nil {
			return err, false
		}
		m.StartIndex = startIndexFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveSearchCertificateRequestStatusFlags(depth int, m *models.SearchCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
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

func retrieveSearchCertificateRequestValidFromFlags(depth int, m *models.SearchCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
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

func retrieveSearchCertificateRequestValidToFlags(depth int, m *models.SearchCertificateRequest, cmdPrefix string, cmd *cobra.Command) (error, bool) {
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

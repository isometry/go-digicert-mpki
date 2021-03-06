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

// Schema cli for GetProfileResponse

// register flags to command
func registerModelGetProfileResponseFlags(depth int, cmdPrefix string, cmd *cobra.Command) error {

	if err := registerGetProfileResponseAuthentication(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetProfileResponseCertificate(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetProfileResponseCertificateDeliveryFormat(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetProfileResponseDuplicateCertPolicy(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetProfileResponseEnrollment(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetProfileResponseID(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetProfileResponseName(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetProfileResponsePrivateKeyAttributes(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetProfileResponsePublishToPublicDirectory(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetProfileResponseRenewalPeriodDays(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetProfileResponseSignatureAlgorithm(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	if err := registerGetProfileResponseStatus(depth, cmdPrefix, cmd); err != nil {
		return err
	}

	return nil
}

func registerGetProfileResponseAuthentication(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	var authenticationFlagName string
	if cmdPrefix == "" {
		authenticationFlagName = "authentication"
	} else {
		authenticationFlagName = fmt.Sprintf("%v.authentication", cmdPrefix)
	}

	if err := registerModelAuthenticationFlags(depth+1, authenticationFlagName, cmd); err != nil {
		return err
	}

	return nil
}

func registerGetProfileResponseCertificate(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	var certificateFlagName string
	if cmdPrefix == "" {
		certificateFlagName = "certificate"
	} else {
		certificateFlagName = fmt.Sprintf("%v.certificate", cmdPrefix)
	}

	if err := registerModelCertificateDetailsFlags(depth+1, certificateFlagName, cmd); err != nil {
		return err
	}

	return nil
}

func registerGetProfileResponseCertificateDeliveryFormat(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	certificateDeliveryFormatDescription := ``

	var certificateDeliveryFormatFlagName string
	if cmdPrefix == "" {
		certificateDeliveryFormatFlagName = "certificate_delivery_format"
	} else {
		certificateDeliveryFormatFlagName = fmt.Sprintf("%v.certificate_delivery_format", cmdPrefix)
	}

	var certificateDeliveryFormatFlagDefault string

	_ = cmd.PersistentFlags().String(certificateDeliveryFormatFlagName, certificateDeliveryFormatFlagDefault, certificateDeliveryFormatDescription)

	return nil
}

func registerGetProfileResponseDuplicateCertPolicy(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	duplicateCertPolicyDescription := ``

	var duplicateCertPolicyFlagName string
	if cmdPrefix == "" {
		duplicateCertPolicyFlagName = "duplicate_cert_policy"
	} else {
		duplicateCertPolicyFlagName = fmt.Sprintf("%v.duplicate_cert_policy", cmdPrefix)
	}

	var duplicateCertPolicyFlagDefault bool

	_ = cmd.PersistentFlags().Bool(duplicateCertPolicyFlagName, duplicateCertPolicyFlagDefault, duplicateCertPolicyDescription)

	return nil
}

func registerGetProfileResponseEnrollment(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	var enrollmentFlagName string
	if cmdPrefix == "" {
		enrollmentFlagName = "enrollment"
	} else {
		enrollmentFlagName = fmt.Sprintf("%v.enrollment", cmdPrefix)
	}

	if err := registerModelEnrollmentFlags(depth+1, enrollmentFlagName, cmd); err != nil {
		return err
	}

	return nil
}

func registerGetProfileResponseID(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	idDescription := ``

	var idFlagName string
	if cmdPrefix == "" {
		idFlagName = "id"
	} else {
		idFlagName = fmt.Sprintf("%v.id", cmdPrefix)
	}

	var idFlagDefault string

	_ = cmd.PersistentFlags().String(idFlagName, idFlagDefault, idDescription)

	return nil
}

func registerGetProfileResponseName(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	nameDescription := ``

	var nameFlagName string
	if cmdPrefix == "" {
		nameFlagName = "name"
	} else {
		nameFlagName = fmt.Sprintf("%v.name", cmdPrefix)
	}

	var nameFlagDefault string

	_ = cmd.PersistentFlags().String(nameFlagName, nameFlagDefault, nameDescription)

	return nil
}

func registerGetProfileResponsePrivateKeyAttributes(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	var privateKeyAttributesFlagName string
	if cmdPrefix == "" {
		privateKeyAttributesFlagName = "private_key_attributes"
	} else {
		privateKeyAttributesFlagName = fmt.Sprintf("%v.private_key_attributes", cmdPrefix)
	}

	if err := registerModelPrivateKeyAttributesFlags(depth+1, privateKeyAttributesFlagName, cmd); err != nil {
		return err
	}

	return nil
}

func registerGetProfileResponsePublishToPublicDirectory(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	publishToPublicDirectoryDescription := ``

	var publishToPublicDirectoryFlagName string
	if cmdPrefix == "" {
		publishToPublicDirectoryFlagName = "publish_to_public_directory"
	} else {
		publishToPublicDirectoryFlagName = fmt.Sprintf("%v.publish_to_public_directory", cmdPrefix)
	}

	var publishToPublicDirectoryFlagDefault bool

	_ = cmd.PersistentFlags().Bool(publishToPublicDirectoryFlagName, publishToPublicDirectoryFlagDefault, publishToPublicDirectoryDescription)

	return nil
}

func registerGetProfileResponseRenewalPeriodDays(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	renewalPeriodDaysDescription := ``

	var renewalPeriodDaysFlagName string
	if cmdPrefix == "" {
		renewalPeriodDaysFlagName = "renewal_period_days"
	} else {
		renewalPeriodDaysFlagName = fmt.Sprintf("%v.renewal_period_days", cmdPrefix)
	}

	var renewalPeriodDaysFlagDefault int32

	_ = cmd.PersistentFlags().Int32(renewalPeriodDaysFlagName, renewalPeriodDaysFlagDefault, renewalPeriodDaysDescription)

	return nil
}

func registerGetProfileResponseSignatureAlgorithm(depth int, cmdPrefix string, cmd *cobra.Command) error {
	if depth > maxDepth {
		return nil
	}

	signatureAlgorithmDescription := ``

	var signatureAlgorithmFlagName string
	if cmdPrefix == "" {
		signatureAlgorithmFlagName = "signature_algorithm"
	} else {
		signatureAlgorithmFlagName = fmt.Sprintf("%v.signature_algorithm", cmdPrefix)
	}

	var signatureAlgorithmFlagDefault string

	_ = cmd.PersistentFlags().String(signatureAlgorithmFlagName, signatureAlgorithmFlagDefault, signatureAlgorithmDescription)

	return nil
}

func registerGetProfileResponseStatus(depth int, cmdPrefix string, cmd *cobra.Command) error {
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

// retrieve flags from commands, and set value in model. Return true if any flag is passed by user to fill model field.
func retrieveModelGetProfileResponseFlags(depth int, m *models.GetProfileResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	retAdded := false

	err, authenticationAdded := retrieveGetProfileResponseAuthenticationFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || authenticationAdded

	err, certificateAdded := retrieveGetProfileResponseCertificateFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || certificateAdded

	err, certificateDeliveryFormatAdded := retrieveGetProfileResponseCertificateDeliveryFormatFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || certificateDeliveryFormatAdded

	err, duplicateCertPolicyAdded := retrieveGetProfileResponseDuplicateCertPolicyFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || duplicateCertPolicyAdded

	err, enrollmentAdded := retrieveGetProfileResponseEnrollmentFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || enrollmentAdded

	err, idAdded := retrieveGetProfileResponseIDFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || idAdded

	err, nameAdded := retrieveGetProfileResponseNameFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || nameAdded

	err, privateKeyAttributesAdded := retrieveGetProfileResponsePrivateKeyAttributesFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || privateKeyAttributesAdded

	err, publishToPublicDirectoryAdded := retrieveGetProfileResponsePublishToPublicDirectoryFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || publishToPublicDirectoryAdded

	err, renewalPeriodDaysAdded := retrieveGetProfileResponseRenewalPeriodDaysFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || renewalPeriodDaysAdded

	err, signatureAlgorithmAdded := retrieveGetProfileResponseSignatureAlgorithmFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || signatureAlgorithmAdded

	err, statusAdded := retrieveGetProfileResponseStatusFlags(depth, m, cmdPrefix, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || statusAdded

	return nil, retAdded
}

func retrieveGetProfileResponseAuthenticationFlags(depth int, m *models.GetProfileResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	authenticationFlagName := fmt.Sprintf("%v.authentication", cmdPrefix)
	if cmd.Flags().Changed(authenticationFlagName) {
		// info: complex object authentication Authentication is retrieved outside this Changed() block
	}
	authenticationFlagValue := m.Authentication
	if swag.IsZero(authenticationFlagValue) {
		authenticationFlagValue = &models.Authentication{}
	}

	err, authenticationAdded := retrieveModelAuthenticationFlags(depth+1, authenticationFlagValue, authenticationFlagName, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || authenticationAdded
	if authenticationAdded {
		m.Authentication = authenticationFlagValue
	}

	return nil, retAdded
}

func retrieveGetProfileResponseCertificateFlags(depth int, m *models.GetProfileResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	certificateFlagName := fmt.Sprintf("%v.certificate", cmdPrefix)
	if cmd.Flags().Changed(certificateFlagName) {
		// info: complex object certificate CertificateDetails is retrieved outside this Changed() block
	}
	certificateFlagValue := m.Certificate
	if swag.IsZero(certificateFlagValue) {
		certificateFlagValue = &models.CertificateDetails{}
	}

	err, certificateAdded := retrieveModelCertificateDetailsFlags(depth+1, certificateFlagValue, certificateFlagName, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || certificateAdded
	if certificateAdded {
		m.Certificate = certificateFlagValue
	}

	return nil, retAdded
}

func retrieveGetProfileResponseCertificateDeliveryFormatFlags(depth int, m *models.GetProfileResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	certificateDeliveryFormatFlagName := fmt.Sprintf("%v.certificate_delivery_format", cmdPrefix)
	if cmd.Flags().Changed(certificateDeliveryFormatFlagName) {

		var certificateDeliveryFormatFlagName string
		if cmdPrefix == "" {
			certificateDeliveryFormatFlagName = "certificate_delivery_format"
		} else {
			certificateDeliveryFormatFlagName = fmt.Sprintf("%v.certificate_delivery_format", cmdPrefix)
		}

		certificateDeliveryFormatFlagValue, err := cmd.Flags().GetString(certificateDeliveryFormatFlagName)
		if err != nil {
			return err, false
		}
		m.CertificateDeliveryFormat = certificateDeliveryFormatFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveGetProfileResponseDuplicateCertPolicyFlags(depth int, m *models.GetProfileResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	duplicateCertPolicyFlagName := fmt.Sprintf("%v.duplicate_cert_policy", cmdPrefix)
	if cmd.Flags().Changed(duplicateCertPolicyFlagName) {

		var duplicateCertPolicyFlagName string
		if cmdPrefix == "" {
			duplicateCertPolicyFlagName = "duplicate_cert_policy"
		} else {
			duplicateCertPolicyFlagName = fmt.Sprintf("%v.duplicate_cert_policy", cmdPrefix)
		}

		duplicateCertPolicyFlagValue, err := cmd.Flags().GetBool(duplicateCertPolicyFlagName)
		if err != nil {
			return err, false
		}
		m.DuplicateCertPolicy = duplicateCertPolicyFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveGetProfileResponseEnrollmentFlags(depth int, m *models.GetProfileResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	enrollmentFlagName := fmt.Sprintf("%v.enrollment", cmdPrefix)
	if cmd.Flags().Changed(enrollmentFlagName) {
		// info: complex object enrollment Enrollment is retrieved outside this Changed() block
	}
	enrollmentFlagValue := m.Enrollment
	if swag.IsZero(enrollmentFlagValue) {
		enrollmentFlagValue = &models.Enrollment{}
	}

	err, enrollmentAdded := retrieveModelEnrollmentFlags(depth+1, enrollmentFlagValue, enrollmentFlagName, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || enrollmentAdded
	if enrollmentAdded {
		m.Enrollment = enrollmentFlagValue
	}

	return nil, retAdded
}

func retrieveGetProfileResponseIDFlags(depth int, m *models.GetProfileResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	idFlagName := fmt.Sprintf("%v.id", cmdPrefix)
	if cmd.Flags().Changed(idFlagName) {

		var idFlagName string
		if cmdPrefix == "" {
			idFlagName = "id"
		} else {
			idFlagName = fmt.Sprintf("%v.id", cmdPrefix)
		}

		idFlagValue, err := cmd.Flags().GetString(idFlagName)
		if err != nil {
			return err, false
		}
		m.ID = idFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveGetProfileResponseNameFlags(depth int, m *models.GetProfileResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	nameFlagName := fmt.Sprintf("%v.name", cmdPrefix)
	if cmd.Flags().Changed(nameFlagName) {

		var nameFlagName string
		if cmdPrefix == "" {
			nameFlagName = "name"
		} else {
			nameFlagName = fmt.Sprintf("%v.name", cmdPrefix)
		}

		nameFlagValue, err := cmd.Flags().GetString(nameFlagName)
		if err != nil {
			return err, false
		}
		m.Name = nameFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveGetProfileResponsePrivateKeyAttributesFlags(depth int, m *models.GetProfileResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	privateKeyAttributesFlagName := fmt.Sprintf("%v.private_key_attributes", cmdPrefix)
	if cmd.Flags().Changed(privateKeyAttributesFlagName) {
		// info: complex object private_key_attributes PrivateKeyAttributes is retrieved outside this Changed() block
	}
	privateKeyAttributesFlagValue := m.PrivateKeyAttributes
	if swag.IsZero(privateKeyAttributesFlagValue) {
		privateKeyAttributesFlagValue = &models.PrivateKeyAttributes{}
	}

	err, privateKeyAttributesAdded := retrieveModelPrivateKeyAttributesFlags(depth+1, privateKeyAttributesFlagValue, privateKeyAttributesFlagName, cmd)
	if err != nil {
		return err, false
	}
	retAdded = retAdded || privateKeyAttributesAdded
	if privateKeyAttributesAdded {
		m.PrivateKeyAttributes = privateKeyAttributesFlagValue
	}

	return nil, retAdded
}

func retrieveGetProfileResponsePublishToPublicDirectoryFlags(depth int, m *models.GetProfileResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	publishToPublicDirectoryFlagName := fmt.Sprintf("%v.publish_to_public_directory", cmdPrefix)
	if cmd.Flags().Changed(publishToPublicDirectoryFlagName) {

		var publishToPublicDirectoryFlagName string
		if cmdPrefix == "" {
			publishToPublicDirectoryFlagName = "publish_to_public_directory"
		} else {
			publishToPublicDirectoryFlagName = fmt.Sprintf("%v.publish_to_public_directory", cmdPrefix)
		}

		publishToPublicDirectoryFlagValue, err := cmd.Flags().GetBool(publishToPublicDirectoryFlagName)
		if err != nil {
			return err, false
		}
		m.PublishToPublicDirectory = publishToPublicDirectoryFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveGetProfileResponseRenewalPeriodDaysFlags(depth int, m *models.GetProfileResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	renewalPeriodDaysFlagName := fmt.Sprintf("%v.renewal_period_days", cmdPrefix)
	if cmd.Flags().Changed(renewalPeriodDaysFlagName) {

		var renewalPeriodDaysFlagName string
		if cmdPrefix == "" {
			renewalPeriodDaysFlagName = "renewal_period_days"
		} else {
			renewalPeriodDaysFlagName = fmt.Sprintf("%v.renewal_period_days", cmdPrefix)
		}

		renewalPeriodDaysFlagValue, err := cmd.Flags().GetInt32(renewalPeriodDaysFlagName)
		if err != nil {
			return err, false
		}
		m.RenewalPeriodDays = renewalPeriodDaysFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveGetProfileResponseSignatureAlgorithmFlags(depth int, m *models.GetProfileResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
	if depth > maxDepth {
		return nil, false
	}
	retAdded := false

	signatureAlgorithmFlagName := fmt.Sprintf("%v.signature_algorithm", cmdPrefix)
	if cmd.Flags().Changed(signatureAlgorithmFlagName) {

		var signatureAlgorithmFlagName string
		if cmdPrefix == "" {
			signatureAlgorithmFlagName = "signature_algorithm"
		} else {
			signatureAlgorithmFlagName = fmt.Sprintf("%v.signature_algorithm", cmdPrefix)
		}

		signatureAlgorithmFlagValue, err := cmd.Flags().GetString(signatureAlgorithmFlagName)
		if err != nil {
			return err, false
		}
		m.SignatureAlgorithm = signatureAlgorithmFlagValue

		retAdded = true
	}

	return nil, retAdded
}

func retrieveGetProfileResponseStatusFlags(depth int, m *models.GetProfileResponse, cmdPrefix string, cmd *cobra.Command) (error, bool) {
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

package cli

import (
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/isometry/go-digicert-mpki/client"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// debug flag indicating that cli should output debug logs
var debug bool

// config file location
var configFile string

// dry run flag
var dryRun bool

// name of the executable
var exeName string = filepath.Base(os.Args[0])

// logDebugf writes debug log to stdout
func logDebugf(format string, v ...interface{}) {
	if !debug {
		return
	}
	log.Printf(format, v...)
}

// depth of recursion to construct model flags
var maxDepth int = 5

// makeClient constructs a client object
func makeClient(cmd *cobra.Command, args []string) (*client.DigicertMpki, error) {
	viper.AutomaticEnv()
	viper.SetEnvPrefix("digicert")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	hostname := viper.GetString("hostname")
	scheme := viper.GetString("scheme")
	api_key := viper.GetString("api-key")

	r := httptransport.New(hostname, client.DefaultBasePath, []string{scheme})
	r.SetDebug(debug)
	// set custom producer and consumer to use the default ones

	r.Consumers["application/json"] = runtime.JSONConsumer()

	// warning: produces */* is not supported by go-swagger cli yet

	r.Producers["application/json"] = runtime.JSONProducer()

	// Configure default authentication
	r.DefaultAuthentication = httptransport.APIKeyAuth("X-API-Key", "header", api_key)

	appCli := client.New(r, strfmt.Default)
	logDebugf("Server url: %v://%v", scheme, hostname)
	return appCli, nil
}

// MakeRootCmd returns the root cmd
func MakeRootCmd() (*cobra.Command, error) {
	cobra.OnInitialize(initViperConfigs)

	// Use executable name as the command name
	rootCmd := &cobra.Command{
		Use: exeName,
	}

	// register basic flags
	rootCmd.PersistentFlags().String("hostname", client.DefaultHost, "hostname of the service")
	viper.BindPFlag("hostname", rootCmd.PersistentFlags().Lookup("hostname"))
	rootCmd.PersistentFlags().String("scheme", client.DefaultSchemes[0], fmt.Sprintf("Choose from: %v", client.DefaultSchemes))
	viper.BindPFlag("scheme", rootCmd.PersistentFlags().Lookup("scheme"))
	rootCmd.PersistentFlags().String("api-key", "", "API key (default from DIGICERT_API_KEY environment variable")
	viper.BindPFlag("api-key", rootCmd.PersistentFlags().Lookup("api-key"))

	// configure debug flag
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "output debug logs")
	// configure config location
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "config file path")
	// configure dry run flag
	rootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "do not send the request to server")

	// register security flags
	// add all operation groups
	operationGroupCertificateEnrollmentCmd, err := makeOperationGroupCertificateEnrollmentCmd()
	if err != nil {
		return nil, err
	}
	rootCmd.AddCommand(operationGroupCertificateEnrollmentCmd)

	operationGroupCertificateProfileCmd, err := makeOperationGroupCertificateProfileCmd()
	if err != nil {
		return nil, err
	}
	rootCmd.AddCommand(operationGroupCertificateProfileCmd)

	operationGroupEnrollStatusCmd, err := makeOperationGroupEnrollStatusCmd()
	if err != nil {
		return nil, err
	}
	rootCmd.AddCommand(operationGroupEnrollStatusCmd)

	operationGroupHelloCmd, err := makeOperationGroupHelloCmd()
	if err != nil {
		return nil, err
	}
	rootCmd.AddCommand(operationGroupHelloCmd)

	operationGroupSearchCertificateCmd, err := makeOperationGroupSearchCertificateCmd()
	if err != nil {
		return nil, err
	}
	rootCmd.AddCommand(operationGroupSearchCertificateCmd)

	operationGroupSeatManagementCmd, err := makeOperationGroupSeatManagementCmd()
	if err != nil {
		return nil, err
	}
	rootCmd.AddCommand(operationGroupSeatManagementCmd)

	operationGroupUserManagementCmd, err := makeOperationGroupUserManagementCmd()
	if err != nil {
		return nil, err
	}
	rootCmd.AddCommand(operationGroupUserManagementCmd)

	// add cobra completion
	rootCmd.AddCommand(makeGenCompletionCmd())

	return rootCmd, nil
}

// initViperConfigs initialize viper config using config file in '$HOME/.config/<cli name>/config.<json|yaml...>'
// currently hostname, scheme and auth tokens can be specified in this config file.
func initViperConfigs() {
	if configFile != "" {
		// use user specified config file location
		viper.SetConfigFile(configFile)
	} else {
		// look for default config
		// Find home directory.
		home, err := homedir.Dir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".cobra" (without extension).
		viper.AddConfigPath(path.Join(home, ".config", exeName))
		viper.SetConfigName("config")
	}

	if err := viper.ReadInConfig(); err != nil {
		logDebugf("Error: loading config file: %v", err)
		return
	}
	logDebugf("Using config file: %v", viper.ConfigFileUsed())
}

func makeOperationGroupCertificateEnrollmentCmd() (*cobra.Command, error) {
	operationGroupCertificateEnrollmentCmd := &cobra.Command{
		Use:  "certificate_enrollment",
		Long: ``,
	}

	operationEnrollCertificateCmd, err := makeOperationCertificateEnrollmentEnrollCertificateCmd()
	if err != nil {
		return nil, err
	}
	operationGroupCertificateEnrollmentCmd.AddCommand(operationEnrollCertificateCmd)

	operationGetCertificateCmd, err := makeOperationCertificateEnrollmentGetCertificateCmd()
	if err != nil {
		return nil, err
	}
	operationGroupCertificateEnrollmentCmd.AddCommand(operationGetCertificateCmd)

	operationRecoverKeyCmd, err := makeOperationCertificateEnrollmentRecoverKeyCmd()
	if err != nil {
		return nil, err
	}
	operationGroupCertificateEnrollmentCmd.AddCommand(operationRecoverKeyCmd)

	operationRenewCertificateCmd, err := makeOperationCertificateEnrollmentRenewCertificateCmd()
	if err != nil {
		return nil, err
	}
	operationGroupCertificateEnrollmentCmd.AddCommand(operationRenewCertificateCmd)

	operationRevokeCertificateCmd, err := makeOperationCertificateEnrollmentRevokeCertificateCmd()
	if err != nil {
		return nil, err
	}
	operationGroupCertificateEnrollmentCmd.AddCommand(operationRevokeCertificateCmd)

	operationUnRevokeCertificateCmd, err := makeOperationCertificateEnrollmentUnRevokeCertificateCmd()
	if err != nil {
		return nil, err
	}
	operationGroupCertificateEnrollmentCmd.AddCommand(operationUnRevokeCertificateCmd)

	return operationGroupCertificateEnrollmentCmd, nil
}
func makeOperationGroupCertificateProfileCmd() (*cobra.Command, error) {
	operationGroupCertificateProfileCmd := &cobra.Command{
		Use:  "certificate_profile",
		Long: ``,
	}

	operationGetAllProfilesCmd, err := makeOperationCertificateProfileGetAllProfilesCmd()
	if err != nil {
		return nil, err
	}
	operationGroupCertificateProfileCmd.AddCommand(operationGetAllProfilesCmd)

	operationGetProfileCmd, err := makeOperationCertificateProfileGetProfileCmd()
	if err != nil {
		return nil, err
	}
	operationGroupCertificateProfileCmd.AddCommand(operationGetProfileCmd)

	return operationGroupCertificateProfileCmd, nil
}
func makeOperationGroupEnrollStatusCmd() (*cobra.Command, error) {
	operationGroupEnrollStatusCmd := &cobra.Command{
		Use:  "enroll_status",
		Long: ``,
	}

	operationEnrollStatusCmd, err := makeOperationEnrollStatusEnrollStatusCmd()
	if err != nil {
		return nil, err
	}
	operationGroupEnrollStatusCmd.AddCommand(operationEnrollStatusCmd)

	return operationGroupEnrollStatusCmd, nil
}
func makeOperationGroupHelloCmd() (*cobra.Command, error) {
	operationGroupHelloCmd := &cobra.Command{
		Use:  "hello",
		Long: ``,
	}

	operationHelloCmd, err := makeOperationHelloHelloCmd()
	if err != nil {
		return nil, err
	}
	operationGroupHelloCmd.AddCommand(operationHelloCmd)

	return operationGroupHelloCmd, nil
}
func makeOperationGroupSearchCertificateCmd() (*cobra.Command, error) {
	operationGroupSearchCertificateCmd := &cobra.Command{
		Use:  "search_certificate",
		Long: ``,
	}

	operationSearchCertCmd, err := makeOperationSearchCertificateSearchCertCmd()
	if err != nil {
		return nil, err
	}
	operationGroupSearchCertificateCmd.AddCommand(operationSearchCertCmd)

	return operationGroupSearchCertificateCmd, nil
}
func makeOperationGroupSeatManagementCmd() (*cobra.Command, error) {
	operationGroupSeatManagementCmd := &cobra.Command{
		Use:  "seat_management",
		Long: ``,
	}

	operationCreateSeatCmd, err := makeOperationSeatManagementCreateSeatCmd()
	if err != nil {
		return nil, err
	}
	operationGroupSeatManagementCmd.AddCommand(operationCreateSeatCmd)

	operationDeleteSeatCmd, err := makeOperationSeatManagementDeleteSeatCmd()
	if err != nil {
		return nil, err
	}
	operationGroupSeatManagementCmd.AddCommand(operationDeleteSeatCmd)

	operationGetSeatCmd, err := makeOperationSeatManagementGetSeatCmd()
	if err != nil {
		return nil, err
	}
	operationGroupSeatManagementCmd.AddCommand(operationGetSeatCmd)

	operationUpdateSeatCmd, err := makeOperationSeatManagementUpdateSeatCmd()
	if err != nil {
		return nil, err
	}
	operationGroupSeatManagementCmd.AddCommand(operationUpdateSeatCmd)

	return operationGroupSeatManagementCmd, nil
}
func makeOperationGroupUserManagementCmd() (*cobra.Command, error) {
	operationGroupUserManagementCmd := &cobra.Command{
		Use:  "user_management",
		Long: ``,
	}

	operationCreatePasscodeCmd, err := makeOperationUserManagementCreatePasscodeCmd()
	if err != nil {
		return nil, err
	}
	operationGroupUserManagementCmd.AddCommand(operationCreatePasscodeCmd)

	operationDeleteEnrollmentCmd, err := makeOperationUserManagementDeleteEnrollmentCmd()
	if err != nil {
		return nil, err
	}
	operationGroupUserManagementCmd.AddCommand(operationDeleteEnrollmentCmd)

	operationGetEnrollmentCmd, err := makeOperationUserManagementGetEnrollmentCmd()
	if err != nil {
		return nil, err
	}
	operationGroupUserManagementCmd.AddCommand(operationGetEnrollmentCmd)

	operationResetPasscodeCmd, err := makeOperationUserManagementResetPasscodeCmd()
	if err != nil {
		return nil, err
	}
	operationGroupUserManagementCmd.AddCommand(operationResetPasscodeCmd)

	return operationGroupUserManagementCmd, nil
}

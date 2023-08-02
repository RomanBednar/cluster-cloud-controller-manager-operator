package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/spf13/cobra"
	"k8s.io/klog/v2"
	"os"
)

const (
	clientIDEnvKey       = "AZURE_CLIENT_ID"
	clientSecretEnvKey   = "AZURE_CLIENT_SECRET"
	tenantIDEnvKey       = "AZURE_TENANT_ID"
	federatedTokenEnvKey = "AZURE_FEDERATED_TOKEN_FILE"

	clientIDCloudConfigKey               = "aadClientId"
	clientSecretCloudConfigKey           = "aadClientSecret"
	useManagedIdentityExtensionConfigKey = "useManagedIdentityExtension"

	tenantIdConfigKey                              = "tenantId"
	aadFederatedTokenFileConfigKey                 = "aadFederatedTokenFile"
	useFederatedWorkloadIdentityExtensionConfigKey = "useFederatedWorkloadIdentityExtension"
)

var (
	injectorCmd = &cobra.Command{
		Use:   "azure-config-credentials-injector [OPTIONS]",
		Short: "Cloud config credentials injection tool for azure cloud platform",
		RunE:  mergeCloudConfig,
	}

	injectorOpts struct {
		cloudConfigFilePath          string
		outputFilePath               string
		enableWorkloadIdentity       string
		disableIdentityExtensionAuth bool
	}
)

func init() {
	klog.InitFlags(flag.CommandLine)
	injectorCmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)
	injectorCmd.PersistentFlags().StringVar(&injectorOpts.cloudConfigFilePath, "cloud-config-file-path", "/tmp/cloud-config/cloud.conf", "Location of the original cloud config file.")
	injectorCmd.PersistentFlags().StringVar(&injectorOpts.outputFilePath, "output-file-path", "/tmp/merged-cloud-config/cloud.conf", "Location of the generated cloud config file with injected credentials.")
	injectorCmd.PersistentFlags().BoolVar(&injectorOpts.disableIdentityExtensionAuth, "disable-identity-extension-auth", false, "Disable managed identity authentication, if it's set in cloudConfig.")
	injectorCmd.PersistentFlags().StringVar(&injectorOpts.enableWorkloadIdentity, "enable-azure-workload-identity", "false", "Enable workload identity authentication.")
}

func main() {
	if err := injectorCmd.Execute(); err != nil {
		klog.Fatal(err)
	}
}

func mergeCloudConfig(_ *cobra.Command, args []string) error {
	var (
		azureClientId string
		err           error
	)

	if _, err := os.Stat(injectorOpts.cloudConfigFilePath); os.IsNotExist(err) {
		return err
	}

	azureClientId, found := mustLookupEnvValue(clientIDEnvKey)
	if !found {
		return fmt.Errorf("%s env variable should be set up", clientIDEnvKey)
	}

	authConfig, err := prepareAuthConfig(injectorOpts.enableWorkloadIdentity)
	if err != nil {
		return fmt.Errorf("could not configure authentication method: %w", err)
	}

	cloudConfig, err := readCloudConfig(injectorOpts.cloudConfigFilePath)
	if err != nil {
		return fmt.Errorf("couldn't read cloud config from file: %w", err)
	}

	preparedCloudConfig, err := prepareCloudConfig(cloudConfig, authConfig, azureClientId)
	if err != nil {
		return fmt.Errorf("couldn't prepare cloud config: %w", err)
	}

	if err := writeCloudConfig(injectorOpts.outputFilePath, preparedCloudConfig); err != nil {
		return fmt.Errorf("couldn't write prepared cloud config to file: %w", err)
	}

	return nil
}

func readCloudConfig(path string) (map[string]interface{}, error) {
	var data map[string]interface{}

	rawData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(rawData, &data); err != nil {
		return nil, err
	}
	return data, nil
}

func prepareAuthConfig(workloadIdentityOpt string) (authConfig map[string]interface{}, err error) {
	authConfig = map[string]interface{}{}
	workloadIdentityRequested := false
	if opt := workloadIdentityOpt; opt == "true" {
		workloadIdentityRequested = true
	}

	clientSecret, secretAvailable := mustLookupEnvValue(clientSecretEnvKey)
	tenantId, tenantIdFound := mustLookupEnvValue(tenantIDEnvKey)
	federatedTokenFile, federatedTokenFileFound := mustLookupEnvValue(federatedTokenEnvKey)
	canSetupWorkloadIdentity := tenantIdFound && federatedTokenFileFound

	useSecret := func() {
		authConfig[clientSecretCloudConfigKey] = clientSecret
	}

	useWorkloadIdentity := func() {
		authConfig[tenantIdConfigKey] = tenantId
		authConfig[aadFederatedTokenFileConfigKey] = federatedTokenFile
		authConfig[useFederatedWorkloadIdentityExtensionConfigKey] = true
	}

	getMissingWorkloadValues := func() []string {
		var missing []string
		if workloadIdentityRequested {
			if !tenantIdFound {
				missing = append(missing, tenantIDEnvKey)
			}
			if !federatedTokenFileFound {
				missing = append(missing, federatedTokenEnvKey)
			}
		} else {
			if !secretAvailable {
				missing = append(missing, clientSecretEnvKey)
			}
		}

		return missing
	}

	switch {
	// All cases when workload identity was requested and should be enabled if possible.
	case workloadIdentityRequested && !canSetupWorkloadIdentity && secretAvailable:
		useSecret()
		klog.Warningf("Workload identity feature should be enabled but required variables are missing: %v\nFalling back to using client secret.", getMissingWorkloadValues())
	case workloadIdentityRequested && !canSetupWorkloadIdentity && !secretAvailable:
		err = fmt.Errorf("Workload identity feature should be enabled but required variables are missing: %v\nFalling back to using client secret also failed because %v variable is missing.", getMissingWorkloadValues(), clientSecretEnvKey)
	case workloadIdentityRequested && canSetupWorkloadIdentity && secretAvailable:
		useWorkloadIdentity()
		klog.Warningf("Enabling workload identity feature but %v variable was found while it should not be present\nPlease consider reporting a bug: https://issues.redhat.com", clientSecretEnvKey)
	case workloadIdentityRequested && canSetupWorkloadIdentity && !secretAvailable:
		klog.Infof("Enabling workload identity feature.")
		useWorkloadIdentity()
	// All cases when workload identity was *not* requested and should stay disabled even if all values are available.
	case !workloadIdentityRequested && !canSetupWorkloadIdentity && !secretAvailable:
		err = fmt.Errorf("enabling client secret authentication failed because %v variable is missing", clientSecretEnvKey)
	case !workloadIdentityRequested && !canSetupWorkloadIdentity && secretAvailable:
		useSecret()
		klog.Infof("Enabling client secret authentication.")
	case !workloadIdentityRequested && canSetupWorkloadIdentity && secretAvailable:
		useSecret()
		klog.Warningf("Enabling client secret authentication, but workload identity values were found %v, %v\nPlease consider reporting a bug: https://issues.redhat.com", tenantId, federatedTokenFile)
	case !workloadIdentityRequested && canSetupWorkloadIdentity && !secretAvailable:
		err = fmt.Errorf("enabling client secret authentication failed because %v variable is missing\nWorkload identity is available, but can not be used because it is explicitly disabled.", clientSecretEnvKey)
	}

	return
}

func prepareCloudConfig(cloudConfig, authConfig map[string]interface{}, clientId string) ([]byte, error) {
	cloudConfig[clientIDCloudConfigKey] = clientId

	if value, found := cloudConfig[useManagedIdentityExtensionConfigKey]; found {
		if injectorOpts.disableIdentityExtensionAuth {
			klog.Infof("%s cleared\n", useManagedIdentityExtensionConfigKey)
			cloudConfig[useManagedIdentityExtensionConfigKey] = false
		} else {
			if value == true {
				klog.Warningf("Warning: %s is set to \"true\", injected credentials may not be used\n", useManagedIdentityExtensionConfigKey)
			}
		}
	}

	for k, v := range authConfig {
		cloudConfig[k] = v
	}

	marshalled, err := json.Marshal(cloudConfig)
	if err != nil {
		return nil, err
	}

	return marshalled, nil
}

func writeCloudConfig(path string, preparedConfig []byte) error {
	if err := os.WriteFile(path, preparedConfig, 0644); err != nil {
		return err
	}
	return nil
}

// lookupWorkloadIdentityEnv loads tenantID and federatedTokenFile values from environment, which are both required for
// workload identity. Return error if any or both values are missing.
func lookupWorkloadIdentityEnv(tenantEnvKey, tokenEnvKey string) (tenantId, federatedTokenFile string, err error) {
	tenantId, tenantIdFound := mustLookupEnvValue(tenantEnvKey)
	federatedTokenFile, federatedTokenFileFound := mustLookupEnvValue(tokenEnvKey)
	klog.V(4).Infof("env vars required for workload identity auth are set to: %v=%v and %v=%v", tenantEnvKey, tenantId, tokenEnvKey, federatedTokenFile)

	if !tenantIdFound && !federatedTokenFileFound {
		err = fmt.Errorf("%v and %v environment variables not found or empty", tenantEnvKey, tokenEnvKey)
		return
	}

	if !tenantIdFound {
		err = fmt.Errorf("%v environment variable not found or empty", tenantEnvKey)
		return
	}

	if !federatedTokenFileFound {
		err = fmt.Errorf("%v environment variable not found or empty", tokenEnvKey)
	}

	return
}

func mustLookupEnvValue(key string) (string, bool) {
	value, found := os.LookupEnv(key)
	if !found || len(value) == 0 {
		return "", false
	}
	return value, true
}

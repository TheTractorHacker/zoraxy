package acme

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/go-acme/lego/v5/challenge"
	"imuslab.com/zoraxy/mod/acme/acmedns"
)

// credentialToInt reads an integer-like credential field sent by the UI as a
// string or by an API client as a JSON number. An unparsable string yields nil
// (the caller keeps its default, as before); any other JSON type is an error
// instead of a panic.
func credentialToInt(raw any, name string) (*int, error) {
	switch v := raw.(type) {
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, nil
		}
		return &n, nil
	case float64:
		n := int(v)
		return &n, nil
	default:
		return nil, fmt.Errorf("DNS credential %q must be a string or a number", name)
	}
}

// Preprocessor function to get DNS challenge provider by name
func GetDnsChallengeProviderByName(dnsProvider string, dnsCredentials string, ppgTimeout int) (challenge.Provider, error) {
	// Unpack the dnsCredentials (json string) to map
	var dnsCredentialsMap map[string]any
	err := json.Unmarshal([]byte(dnsCredentials), &dnsCredentialsMap)
	if err != nil {
		return nil, err
	}

	// Clear the PollingInterval and PropagationTimeout field and conert to int
	userDefinedPollingInterval := 2
	if dnsCredentialsMap["PollingInterval"] != nil {
		convertedPollingInterval, err := credentialToInt(dnsCredentialsMap["PollingInterval"], "PollingInterval")
		if err != nil {
			return nil, err
		}
		delete(dnsCredentialsMap, "PollingInterval")
		if convertedPollingInterval != nil {
			userDefinedPollingInterval = *convertedPollingInterval
		}
	}

	userDefinedPropagationTimeout := ppgTimeout
	if dnsCredentialsMap["PropagationTimeout"] != nil {
		convertedPropagationTimeout, err := credentialToInt(dnsCredentialsMap["PropagationTimeout"], "PropagationTimeout")
		if err != nil {
			return nil, err
		}
		delete(dnsCredentialsMap, "PropagationTimeout")
		if convertedPropagationTimeout != nil {
			// Overwrite the default propagation timeout if it is requeted from UI
			userDefinedPropagationTimeout = *convertedPropagationTimeout
		}
	}

	if dnsProvider == "plesk" {
		return newPleskProvider(dnsCredentialsMap, userDefinedPropagationTimeout, userDefinedPollingInterval)
	}

	providerConfigStructure, err := acmedns.GetProviderConfigStructure(dnsProvider)
	if err != nil {
		return nil, err
	}

	var hostURL *url.URL = nil
	for configTitle, configDataType := range providerConfigStructure {
		if configDataType == "*url.URL" {
			// Extract the hostURL from dnsCredentialsMap and delete it from the map
			// Prevent Unmarshal error when try to unmarshal the json to provider config struct on *url.URL type (ex. powerdns Host field)
			urlStrRaw := dnsCredentialsMap[configTitle]
			if urlStrRaw == nil {
				// If the url field is not provided, check next *url.URL field
				continue
			}
			urlStr, ok := urlStrRaw.(string)
			if !ok {
				return nil, fmt.Errorf("DNS credential %q must be a string URL", configTitle)
			}
			delete(dnsCredentialsMap, configTitle)
			hostURL, err = url.Parse(urlStr)
			if err != nil {
				return nil, err
			}
			// Select first field
			break
		}
	}

	// Restructure dnsCredentials string from map
	dnsCredentialsBytes, err := json.Marshal(dnsCredentialsMap)
	if err != nil {
		return nil, err
	}
	dnsCredentials = string(dnsCredentialsBytes)

	// Using acmedns CICD pipeline generated datatype to optain the DNS provider
	return acmedns.GetDNSProviderByJsonConfig(
		dnsProvider,
		dnsCredentials,
		int64(userDefinedPropagationTimeout),
		int64(userDefinedPollingInterval),
		hostURL,
	)
}

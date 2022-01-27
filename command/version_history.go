package command

import (
	"fmt"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"
	"github.com/ryanuber/columnize"
	"strings"
)

var (
	_ cli.Command             = (*VersionHistoryCommand)(nil)
	_ cli.CommandAutocomplete = (*VersionHistoryCommand)(nil)
)

// VersionHistoryCommand is a Command implementation prints the version.
type VersionHistoryCommand struct {
	*BaseCommand
}

func (c *VersionHistoryCommand) Synopsis() string {
	return "Prints the version history of the target Vault server"
}

func (c *VersionHistoryCommand) Help() string {
	helpText := `
Usage: vault version

  Prints the version history of the target Vault server.

  Print the version history:

      $ vault version-history
` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *VersionHistoryCommand) Flags() *FlagSets {
	return c.flagSet(FlagSetOutputFormat)
}

func (c *VersionHistoryCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *VersionHistoryCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

const versionTrackingWarning = "Note: Version tracking was added in 1.9.0. Earlier versions have not been tracked."

func (c *VersionHistoryCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(err.Error())
		return 2
	}

	resp, err := client.Logical().List("sys/version-history")
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading version history: %s", err))
		return 2
	}

	if c.flagFormat == "json" {
		c.UI.Warn("")
		c.UI.Warn(versionTrackingWarning)
		c.UI.Warn("")

		return OutputData(c.UI, resp)
	}

	if resp == nil || resp.Data == nil {
		c.UI.Error("Invalid response returned from Vault")
		return 2
	}

	var keyInfo map[string]interface{}

	keys, ok := extractListData(resp)
	if !ok {
		c.UI.Error("Expected keys in response to be an array")
		return 2
	}

	keyInfo, ok = resp.Data["key_info"].(map[string]interface{})
	if !ok {
		c.UI.Error("Expected key_info in response to be a map")
		return 2
	}

	table := []string{"Version | Installation Time"}
	columnConfig := columnize.DefaultConfig()
	columnConfig.Glue = "   "

	for _, versionRaw := range keys {
		version, ok := versionRaw.(string)

		if !ok {
			c.UI.Error("Expected version to be string")
			return 2
		}

		versionInfoRaw := keyInfo[version]

		versionInfo, ok := versionInfoRaw.(map[string]interface{})
		if !ok {
			c.UI.Error(fmt.Sprintf("Expected version info for %q to be map", version))
			return 2
		}

		table = append(table, fmt.Sprintf("%s | %s", version, versionInfo["timestamp_installed"]))
	}

	c.UI.Warn("")
	c.UI.Warn(versionTrackingWarning)
	c.UI.Warn("")
	c.UI.Output(tableOutput(table, columnConfig))

	return 0
}

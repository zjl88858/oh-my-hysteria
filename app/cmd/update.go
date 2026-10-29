// SPDX-License-Identifier: MIT-0

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Retain the command for compatibility, without querying upstream releases.
var checkUpdateCmd = &cobra.Command{
	Use:   "check-update",
	Short: "Show update-source status",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := fmt.Fprintln(cmd.OutOrStdout(), "oh-my-hysteria: no fork update source is configured; upstream update checks are disabled.")
		return err
	},
}

func init() {
	rootCmd.AddCommand(checkUpdateCmd)
}

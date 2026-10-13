package cmd

import (
	"encoding/json"

	"github.com/karust/openserp/core"
	"github.com/spf13/cobra"
)

func newKeygenCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "keygen [key-id]",
		Short: "Generate a user API key and the hash to store in auth.keys",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, hash, err := core.GenerateAPIKey()
			if err != nil {
				return err
			}
			cfg, err := core.NormalizeAuthConfig(core.AuthConfig{
				Enabled: true,
				Keys:    []core.APIKeyConfig{{ID: args[0], KeyHash: hash}},
			})
			if err != nil {
				return err
			}
			// Generated entries inherit the server's configured rate defaults.
			cfg.Keys[0].RateRequests, cfg.Keys[0].RateBurst = 0, 0
			return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
				APIKey string            `json:"api_key"`
				Config core.APIKeyConfig `json:"config"`
			}{APIKey: key, Config: cfg.Keys[0]})
		},
	}
}

func init() {
	RootCmd.AddCommand(newKeygenCommand())
}

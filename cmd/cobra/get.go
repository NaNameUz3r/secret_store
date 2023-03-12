package cobra

import (
	"fmt"

	"github.com/NaNameUz3r/secret_store/secret"
	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Fetches a secrets value from encrypted file, if key exists ",
	Run: func(cmd *cobra.Command, args []string) {
		vault := secret.FileVault(cryptKey, secretStorePath())
		key := args[0]
		value, err := vault.Get(key)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s=%s\n", key, value)
	},
}

func init() {
	RootCmd.AddCommand(getCmd)
}

package cobra

import (
	"fmt"

	"github.com/NaNameUz3r/secret_store/secret"
	"github.com/spf13/cobra"
)

var setCmd = &cobra.Command{
	Use:   "set",
	Short: "Sets a secret in encrypted file",
	Run: func(cmd *cobra.Command, args []string) {
		vault := secret.FileVault(cryptKey, secretStorePath())
		key, value := args[0], args[1]
		err := vault.Set(key, value)
		if err != nil {
			panic(err)
		}
		fmt.Println("Secret stored successfully.")
	},
}

func init() {
	RootCmd.AddCommand(setCmd)
}

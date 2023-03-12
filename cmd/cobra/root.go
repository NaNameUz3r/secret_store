package cobra

import (
	"path/filepath"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use:   "secret",
	Short: "Secret is an API key-val secret manager",
}

var cryptKey string

func init() {
	RootCmd.PersistentFlags().StringVarP(&cryptKey, "key", "k", "", "the key is used to decode and encode secrets")
}

func secretStorePath() string {
	home, _ := homedir.Dir()
	storePath := filepath.Join(home, ".secret-store")
	return storePath
}

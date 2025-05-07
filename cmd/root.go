package cmd

import (
	"escalato/internal/utils"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "escalato",
	Short: "Escalato - tool for managing AWS IAM",
	Long: `Escalato is a tool for managing and displaying AWS IAM information.
It currently supports displaying users and roles`,
}

func Execute() error {
	utils.DisplayBanner()

	return rootCmd.Execute()
}
func init() {
	rootCmd.PersistentFlags().StringP("profile", "p", "", "Profil AWS")
	rootCmd.PersistentFlags().StringP("region", "r", "us-east-1", "Region AWS")
}

func er(msg interface{}) {
	fmt.Println("Error:", msg)
	os.Exit(1)
}

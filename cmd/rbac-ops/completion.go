package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// completionCmd represents the completion command
var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate completion script",
	Long: `To load completions:

Bash:
  $ source <(rbac-ops completion bash)

Zsh:
  $ source <(rbac-ops completion zsh)

fish:
  $ rbac-ops completion fish | source

PowerShell:
  PS> rbac-ops completion powershell | Out-String | Invoke-Expression
`,
	ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
	Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			if err := cmd.Root().GenBashCompletion(os.Stdout); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		case "zsh":
			if err := cmd.Root().GenZshCompletion(os.Stdout); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		case "fish":
			if err := cmd.Root().GenFishCompletion(os.Stdout, true); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		case "powershell":
			if err := cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
	},
}

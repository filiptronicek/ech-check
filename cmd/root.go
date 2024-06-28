package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/filiptronicek/ech/pkg"
	"github.com/spf13/cobra"
)

func reportDomain(domain string, hasECH, hasKyber bool) {
	echEmoji := "❌"
	kyberEmoji := "❌"

	if hasECH {
		echEmoji = "✅"
	}
	if hasKyber {
		kyberEmoji = "✅"
	}

	fmt.Printf("%s: ECH: %s, Kyber: %s\n", domain, echEmoji, kyberEmoji)
}

func PrintVerbose(log string) {
	if verbose {
		fmt.Println(log)
	}
}

var domainsCsvPath string
var verbose bool
var rootCmd = &cobra.Command{
	Use:   "sec-check",
	Short: "A tool for checking ECH and Kyber support in domains",
	Args:  cobra.MinimumNArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		logLevel := slog.LevelInfo
		if verbose {
			logLevel = slog.LevelDebug
		}
		logger := pkg.SetupHumanLogger(logLevel)
		slog.SetDefault(logger)

		var domains []string
		var err error
		if domainsCsvPath != "" {
			domains, err = pkg.FetchPopularDomainsFromFile(domainsCsvPath, 10000)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
		} else {
			domains = args
		}

		totalDomains := len(domains)
		totalKyber := 0
		totalECH := 0
		for _, domain := range domains {
			err, result := pkg.CheckKyberSupport(domain)
			if err != nil {
				fmt.Printf(domain + " not accessible\n")
				continue
			}

			if result.HasECH {
				totalECH++
			}

			if result.HasKyber {
				totalKyber++
			}

			reportDomain(domain, result.HasECH, result.HasKyber)
		}

		if totalDomains > 1 {
			fmt.Printf("Total domains: %d\n", totalDomains)
			fmt.Printf("Total support ECH: %d\n", totalECH)
			fmt.Printf("Total support Kyber: %d\n", totalKyber)
		}

		return
	},
}

func Execute() {
	rootCmd.Flags().StringVarP(&domainsCsvPath, "domains", "t", "", "Check against a list of domains from a CSV file")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Print more information")
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

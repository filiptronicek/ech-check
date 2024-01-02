package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
)

type DomainData struct {
	Domain string
}

type Result struct {
	Domain   string
	HasECH   bool
	HasHTTPS bool
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <file_path>", os.Args[0])
	}
	filePath := os.Args[1]

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	_, err = reader.Read()
	if err != nil {
		log.Fatalf("Error reading header: %v", err)
	}

	const numGoroutines = 12
	jobs := make(chan DomainData, numGoroutines)
	results := make(chan Result, numGoroutines)
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go processDomains(jobs, results, &wg)
	}

	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				close(jobs)
				return
			}
			jobs <- DomainData{Domain: record[0]}
		}
	}()

	// Close results channel once all jobs are done
	go func() {
		wg.Wait()
		close(results)
	}()

	var totalDomains, echDomains, httpsDomains int
	var echEnabledDomains []string

	for r := range results {
		totalDomains++
		if r.HasECH {
			echDomains++
			echEnabledDomains = append(echEnabledDomains, r.Domain)
		} else if r.HasHTTPS {
			httpsDomains++
		}

		if totalDomains%10 == 0 {
			displayStats(totalDomains, echDomains, httpsDomains)
		}
	}

	err = writeStatsToCSV(totalDomains, httpsDomains, echDomains, "output.csv")
	if err != nil {
		log.Fatalf("Error writing to CSV: %v", err)
	}

	fmt.Println("ech-enabled domains:")
	for _, domain := range echEnabledDomains {
		fmt.Println(domain)
	}
}

func writeStatsToCSV(total, https, ech int, filename string) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	record := []string{"domains", "https_dns", "ech"}
	if fileStat, _ := file.Stat(); fileStat.Size() == 0 {
		// Write header only if file is new
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	record = []string{fmt.Sprintf("%d", total), fmt.Sprintf("%d", https), fmt.Sprintf("%d", ech)}
	if err := writer.Write(record); err != nil {
		return err
	}

	return nil
}

func processDomains(jobs <-chan DomainData, results chan<- Result, wg *sync.WaitGroup) {
	defer wg.Done()
	for data := range jobs {
		cmd := exec.Command("kdig", data.Domain, "+noall", "+answer", "-t", "TYPE65", "+timeout=1")
		output, err := cmd.Output()
		if err != nil {
			log.Printf("Error executing kdig for domain %s: %v", data.Domain, err)
		}

		hasECH := strings.Contains(string(output), "ech=")
		hasHTTPS := len(string(output)) > 0
		results <- Result{Domain: data.Domain, HasECH: hasECH, HasHTTPS: hasHTTPS}
	}
}

func displayStats(total int, echCount int, httpsCount int) {
	fmt.Printf("Processed Domains: %d\n", total)
	fmt.Printf("Domains with 'ech=': %d\n", echCount)
	fmt.Printf("Domains with HTTPS record (without 'ech='): %d\n", httpsCount)
	fmt.Println("-----------------------")
}

package pkg

import (
	"encoding/csv"
	"fmt"
	"os"
)

func FetchPopularDomainsFromFile(filePath string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 100 // Default limit
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	var domains []string

	// Skip the header
	if _, err := reader.Read(); err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	count := 0
	for {
		if count >= limit {
			break
		}

		record, err := reader.Read()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("failed to read record: %w", err)
		}
		domains = append(domains, record[0])
		count++
	}

	return domains, nil
}

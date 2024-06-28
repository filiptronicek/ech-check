package pkg

import (
	"fmt"
	"regexp"
)

// extractECH extracts the ECH value from the input string using regular expressions.
func ExtractECH(input string) (string, error) {
	re := regexp.MustCompile(`ech="([^"]+)"`)
	matches := re.FindStringSubmatch(input)
	if len(matches) < 2 {
		return "", fmt.Errorf("ech value not found")
	}
	return matches[1], nil
}

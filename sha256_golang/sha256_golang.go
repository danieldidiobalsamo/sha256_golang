package sha256_golang

import (
	"errors"
	"fmt"
)

func Hello(name string) (string, error) {
	if name == "" {
		return "", errors.New("empty name")
	}

	msg := fmt.Sprintf("Hello %v", name)
	return msg, nil
}

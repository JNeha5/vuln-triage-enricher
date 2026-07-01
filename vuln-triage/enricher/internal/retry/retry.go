// 503 Service Unavailable
// Timeout
// Temporary network issue
// Added retry support for external API calls to improve resilience against temporary network failures and service interruptions.
package retry

import (
	"errors"
	"time"
)

func Do(operation func() error) error {

	maxRetries := 3

	for i := 0; i < maxRetries; i++ {

		err := operation()

		if err == nil {
			return nil
		}

		time.Sleep(2 * time.Second)
	}

	return errors.New("operation failed after retries")
}

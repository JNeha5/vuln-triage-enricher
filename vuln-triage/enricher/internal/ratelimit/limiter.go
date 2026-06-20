// 429 Too Many Requests
package ratelimit

import "time"

func Wait() {
	time.Sleep(1 * time.Second)
}

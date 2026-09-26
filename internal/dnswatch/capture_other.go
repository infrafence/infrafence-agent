//go:build !linux

package dnswatch

import (
	"context"
	"errors"
)

func capture(ctx context.Context, ready func(), fn func(p Packet)) error {
	return errors.New("DNS inspection needs Linux")
}

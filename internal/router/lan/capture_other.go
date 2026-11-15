//go:build !linux

package lan

import (
	"context"
	"errors"
)

func CaptureDNS(ctx context.Context, ifname string, fn func(DNSPacket)) error {
	return errors.New("DNS capture needs Linux")
}

//go:build !linux

package scanwatch

import (
	"context"
	"errors"
	"net"
)

func capture(ctx context.Context, ready func(), fn func(net.IP, uint16)) error {
	return errors.New("port scan detection needs Linux")
}

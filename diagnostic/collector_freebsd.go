//go:build freebsd

package diagnostic

import (
	"context"
	"fmt"
)

type NetworkCollectorImpl struct{}

func (c *NetworkCollectorImpl) Collect(
	_ context.Context,
	_ TraceOptions,
) ([]*Hop, string, error) {
	return nil, "", fmt.Errorf("network diagnostics not supported on FreeBSD")
}

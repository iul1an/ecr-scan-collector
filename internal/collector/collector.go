package collector

import (
	"context"
)

// LogCollector defines the interface for different log collection strategies.
type LogCollector interface {
	Index(ctx context.Context, jsonData []byte) error
}

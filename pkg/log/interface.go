package logger

import "context"

type Logger interface {
	Log(ctx context.Context, subsystem string, level int, action string, fields map[string]string)
}

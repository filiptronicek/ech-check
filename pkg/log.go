package pkg

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

type EmojiHandler struct {
	level slog.Level
}

func (h *EmojiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *EmojiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

func (h *EmojiHandler) WithGroup(name string) slog.Handler {
	return h
}

func (h *EmojiHandler) Handle(ctx context.Context, record slog.Record) error {
	var emoji string
	switch record.Level {
	case slog.LevelDebug:
		emoji = "🐛"
	case slog.LevelInfo:
		emoji = "ℹ️"
	case slog.LevelWarn:
		emoji = "⚠️"
	case slog.LevelError:
		emoji = "❌"
	default:
		emoji = "🔍"
	}

	msg := record.Message
	var context string
	record.Attrs(func(a slog.Attr) bool {
		context += fmt.Sprintf("%s=%v ", a.Key, a.Value)
		return true
	})

	formatted := fmt.Sprintf("%s %s - %s\n", emoji, msg, context)
	_, err := os.Stdout.Write([]byte(formatted))
	return err
}

func SetupHumanLogger(level slog.Level) *slog.Logger {
	handler := &EmojiHandler{level: level}

	logger := slog.New(handler)
	return logger
}

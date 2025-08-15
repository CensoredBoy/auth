package logger

import (
	"context"
	"fmt"
	"google.golang.org/grpc/metadata"
	"net/http"
	"os"
	"strings"
	"time"
)

func (l *CEFLogger) getActor(ctx context.Context) string {
	// 1. Пробуем взять из gRPC метаданных
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if users := md.Get("x-user"); len(users) > 0 {
			return users[0]
		}
	}

	// 2. Пробуем из HTTP-заголовков (для REST)
	if req, ok := ctx.Value("httpRequest").(*http.Request); ok {
		if user := req.Header.Get("X-User-Email"); user != "" {
			return user
		}
	}

	// 3. Дефолтное значение
	return "system"
}

func escapeCEFValue(value string) string {
	var builder strings.Builder

	for _, ch := range value {
		switch ch {
		case '\\':
			builder.WriteString(`\\`)
		case '|':
			builder.WriteString(`\|`)
		case '=':
			builder.WriteString(`\=`)
		case '\n':
			builder.WriteString(`\n`)
		case '\r':
			builder.WriteString(`\r`)
		default:
			builder.WriteRune(ch)
		}
	}

	return builder.String()
}

type CEFLogger struct {
	appName  string
	minLevel int // Минимальный уровень логирования (10=DEBUG, 1=EMERGENCY)
}

// Уровни severity (CEF)
const (
	LevelDebug = 8
	LevelInfo  = 7
	LevelWarn  = 5
	LevelError = 3
	LevelCrit  = 1
)

func NewCEFLogger(appName string) *CEFLogger {
	return &CEFLogger{
		appName:  appName,
		minLevel: LevelInfo, // По умолчанию логируем от INFO и выше
	}
}

// Log - основной метод логирования
func (l *CEFLogger) Log(ctx context.Context, subsystem string, level int, action string, fields map[string]string) {
	if level > l.minLevel { // Фильтрация по уровню
		return
	}

	// Формируем CEF-запись
	cef := fmt.Sprintf(
		"CEF:0|YourCompany|%s|1.0|%s|%s|%d|%s",
		l.appName,
		subsystem,
		action,
		10-level, // Конвертируем в CEF-шкалу (10-8=2 для DEBUG)
		l.buildExtensions(ctx, fields),
	)

	fmt.Fprintln(os.Stdout, cef) // Или пишем в файл/отправляем в SIEM
}

// buildExtensions формирует расширения для CEF
func (l *CEFLogger) buildExtensions(ctx context.Context, fields map[string]string) string {
	ext := []string{
		"time=" + time.Now().Format(time.RFC3339),
		"act=" + l.getActor(ctx),
	}

	for k, v := range fields {
		ext = append(ext, fmt.Sprintf("%s=%s", k, escapeCEFValue(v)))
	}

	return strings.Join(ext, " ")
}
